#!/usr/bin/env python3
import os
import re
import subprocess
import time
from dataclasses import dataclass

from ebpf_event_oracles import (
    parse_json_events,
    parse_lifecycle_events,
    parse_stats_events,
)
from ebpf_semantic_checks import valid_stats_event
from ebpf_suites import build_named_fixture, build_strace_go, run_strace_go_json


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PERF_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_perf_fixture.c")
RUNTIME_DIAGNOSTIC_FIELDS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)
GO_BENCHMARK_PATTERN = re.compile(
    r"^(?P<name>Benchmark\S+)\s+\d+\s+"
    r"(?P<ns>[0-9]+(?:\.[0-9]+)?)\s+ns/op\s+"
    r"(?P<bytes>[0-9]+(?:\.[0-9]+)?)\s+B/op\s+"
    r"(?P<allocs>[0-9]+(?:\.[0-9]+)?)\s+allocs/op(?:\s+.*)?$"
)


@dataclass(frozen=True)
class PerfWorkloadSpec:
    name: str
    minimum_exit_counts: tuple
    fixture_args: tuple = ()
    trace: str = ""
    payload_requirements: tuple = ()
    lifecycle_actions: tuple = ()
    require_non_leader_tid: bool = False


@dataclass
class PerfCapture:
    name: str
    result: object
    elapsed: float
    events: list
    lifecycle_events: list
    stats_events: list

    @property
    def exit_events(self):
        return [event for event in self.events if event.get("event_type") == "exit"]


PERF_WORKLOADS = (
    PerfWorkloadSpec(
        name="scalar",
        fixture_args=("scalar", "1500"),
        trace="getpid,clock_gettime",
        minimum_exit_counts=(("getpid", 1500), ("clock_gettime", 1500)),
    ),
    PerfWorkloadSpec(
        name="io",
        fixture_args=("io", "1000"),
        trace="read,write",
        minimum_exit_counts=(("read", 1000), ("write", 1000)),
        payload_requirements=(("read", "out", 1), ("write", "in", 1)),
    ),
    PerfWorkloadSpec(
        name="lifecycle",
        fixture_args=("lifecycle", "8"),
        trace="fork,vfork,clone,clone3,execve",
        minimum_exit_counts=(("execve", 1),),
        lifecycle_actions=("fork", "exec", "exit"),
    ),
    PerfWorkloadSpec(
        name="threads",
        fixture_args=("threads", "4", "400"),
        trace="getpid,clone,clone3",
        minimum_exit_counts=(("getpid", 1000),),
        require_non_leader_tid=True,
    ),
)


def parse_go_benchmark_metrics(output):
    metrics = []
    for line in output.splitlines():
        match = GO_BENCHMARK_PATTERN.match(line.strip())
        if not match:
            continue
        metrics.append(
            {
                "name": match.group("name"),
                "ns_per_op": float(match.group("ns")),
                "bytes_per_op": float(match.group("bytes")),
                "allocs_per_op": float(match.group("allocs")),
            }
        )
    return metrics


def run_go_pipeline_benchmarks():
    return subprocess.run(
        [
            "go",
            "test",
            "./cmd/strace-go",
            "-run",
            "^$",
            "-bench",
            "^Benchmark(TraceEventDecodeState|JSONEventWriter|JSONDecodedEventWriter|JSONDecodedPayloadEventWriter)$",
            "-benchmem",
            "-count=1",
        ],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=120,
    )


def _event_count(events, syscall, event_type="exit"):
    return sum(
        1
        for event in events
        if event.get("syscall") == syscall and event.get("event_type") == event_type
    )


def _has_payload(events, syscall, direction, arg_index):
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != "exit":
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == direction
                and section.get("arg_index") == arg_index
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
            ):
                return True
    return False


def _paired_failures(events, syscalls):
    failures = []
    for syscall in syscalls:
        unpaired = [
            event
            for event in events
            if event.get("syscall") == syscall
            and event.get("event_type") == "exit"
            and not event.get("paired_enter")
        ]
        if unpaired:
            failures.append(f"{syscall} has {len(unpaired)} unpaired exit events")
    return failures


def validate_perf_capture(capture, spec):
    failures = []
    if capture.result.returncode != 0:
        failures.append(f"{spec.name} fixture rc={capture.result.returncode}")
    if len(capture.stats_events) != 1:
        failures.append(f"{spec.name} stats event count={len(capture.stats_events)}")
    stats = capture.stats_events[0] if capture.stats_events else {}
    if not valid_stats_event(stats):
        failures.append(f"{spec.name} stats event is invalid")
    for counter in RUNTIME_DIAGNOSTIC_FIELDS:
        if stats.get(counter, 1) != 0:
            failures.append(f"{spec.name} {counter}={stats.get(counter)}")

    required_syscalls = []
    for syscall, minimum in spec.minimum_exit_counts:
        required_syscalls.append(syscall)
        actual = _event_count(capture.events, syscall)
        if actual < minimum:
            failures.append(f"{spec.name} {syscall} exits={actual}, want>={minimum}")
    failures.extend(_paired_failures(capture.events, required_syscalls))
    for syscall, direction, arg_index in spec.payload_requirements:
        if not _has_payload(capture.events, syscall, direction, arg_index):
            failures.append(f"{spec.name} {syscall} {direction} payload missing")
    for action in spec.lifecycle_actions:
        if not any(event.get("action") == action for event in capture.lifecycle_events):
            failures.append(f"{spec.name} lifecycle {action} missing")
    if spec.require_non_leader_tid and not any(
        event.get("event_type") == "exit" and event.get("tid") != event.get("pid")
        for event in capture.events
    ):
        failures.append(f"{spec.name} non-leader TID event missing")
    return failures


def capture_workload(fixture, spec):
    command_args = ["-f", "-e", f"trace={spec.trace}", fixture]
    command_args.extend(spec.fixture_args)
    start = time.monotonic()
    result = run_strace_go_json(command_args, timeout=60)
    return PerfCapture(
        name=spec.name,
        result=result,
        elapsed=time.monotonic() - start,
        events=parse_json_events(result.stderr),
        lifecycle_events=parse_lifecycle_events(result.stderr),
        stats_events=parse_stats_events(result.stderr),
    )


def print_perf_capture(capture):
    stats = capture.stats_events[0] if capture.stats_events else {}
    print(f"=== EBPF PERF {capture.name} ===")
    print(f"returncode: {capture.result.returncode}")
    print(f"elapsed_sec: {capture.elapsed:.6f}")
    print(f"json_events: {len(capture.events)}")
    print(f"exit_events: {len(capture.exit_events)}")
    print(f"lifecycle_events: {len(capture.lifecycle_events)}")
    for counter in RUNTIME_DIAGNOSTIC_FIELDS:
        print(f"{counter}: {stats.get(counter)}")
    if capture.elapsed > 0:
        print(f"events_per_sec: {len(capture.exit_events) / capture.elapsed:.2f}")


def print_go_pipeline_benchmarks(result, metrics):
    print("=== GO PERF event-pipeline ===")
    print(f"returncode: {result.returncode}")
    for metric in metrics:
        print(
            f"{metric['name']}: ns/op={metric['ns_per_op']:.2f} "
            f"B/op={metric['bytes_per_op']:.2f} "
            f"allocs/op={metric['allocs_per_op']:.2f}"
        )


def run_ebpf_perf(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_named_fixture(
        "strace-go-ebpf-perf-fixture", PERF_FIXTURE_SRC, ["-pthread"]
    )
    failed = False
    try:
        benchmark_result = run_go_pipeline_benchmarks()
    except (OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: Go event-pipeline benchmark failed to run: {error}")
        failed = True
    else:
        benchmark_output = benchmark_result.stdout + benchmark_result.stderr
        benchmark_metrics = parse_go_benchmark_metrics(benchmark_output)
        print_go_pipeline_benchmarks(benchmark_result, benchmark_metrics)
        expected_benchmarks = {
            "BenchmarkTraceEventDecodeState",
            "BenchmarkJSONEventWriter",
            "BenchmarkJSONDecodedEventWriter",
            "BenchmarkJSONDecodedPayloadEventWriter",
        }
        actual_benchmarks = {
            metric["name"].rsplit("-", 1)[0] for metric in benchmark_metrics
        }
        missing = expected_benchmarks - actual_benchmarks
        if benchmark_result.returncode != 0:
            failed = True
            print("FAIL: Go event-pipeline benchmark returned nonzero")
            print("\n".join(benchmark_output.splitlines()[-30:]))
        elif missing:
            failed = True
            print(f"FAIL: missing Go benchmark metrics: {sorted(missing)}")
    for spec in PERF_WORKLOADS:
        capture = capture_workload(fixture, spec)
        print_perf_capture(capture)
        failures = validate_perf_capture(capture, spec)
        if failures:
            failed = True
            for failure in failures:
                print(f"FAIL: {failure}")
            print("--- stderr tail ---")
            print("\n".join(capture.result.stderr.splitlines()[-30:]))
    if failed:
        return 1
    print("PASS: ebpf-perf")
    return 0
