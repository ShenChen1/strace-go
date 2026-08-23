#!/usr/bin/env python3
import json
import os
import time
from dataclasses import dataclass

from ebpf_check_support import service_measurement_failures, valid_stats_event
from ebpf_event_oracles import (
    parse_phase_events,
    parse_ready_events,
    parse_stats_events,
)
from ebpf_fixture_build import build_named_fixture
from ebpf_suites import (
    build_strace_go,
    run_strace_go_json,
    run_strace_go_capture,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PERF_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_perf_fixture.c")
THREAD_COUNT = "16"
ITERATIONS = "100000"
LONG_THREAD_COUNT = "32"
LONG_ITERATIONS = "100000"
MIXED_ITERATIONS = "100000"
SMALL_ITERATIONS = "100000"
EXPECTED_JSON_SYSCALL_EVENTS = int(THREAD_COUNT) * int(ITERATIONS)
MIN_LONG_PRODUCER_ATTEMPTS = 2 * int(LONG_THREAD_COUNT) * int(LONG_ITERATIONS)
CAPTURE_ZERO_DIAGNOSTICS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)
CAPTURE_PRESSURE_ZERO_DIAGNOSTICS = CAPTURE_ZERO_DIAGNOSTICS[1:]
LONG_CAPTURE_TIMEOUT_SECONDS = 180


@dataclass
class CaptureRun:
    name: str
    result: object
    elapsed: float
    syscall_events: int
    ready_events: list
    phase_events: list
    stats_events: list
    text_syscall_events: int = 0
    allow_reserve_fail: bool = False


def _fixture_args(fixture, workload="threads"):
    if workload == "scalar":
        return [
            "-e",
            "trace=getpid,clock_gettime",
            fixture,
            "scalar",
            MIXED_ITERATIONS,
        ]
    if workload == "small":
        return [
            "-e",
            "trace=arch_prctl,get_robust_list",
            fixture,
            "small",
            SMALL_ITERATIONS,
        ]
    if workload == "long":
        return [
            "-f",
            "-e",
            "trace=getpid",
            fixture,
            "threads",
            LONG_THREAD_COUNT,
            LONG_ITERATIONS,
        ]
    return ["-f", "-e", "trace=getpid", fixture, "threads", THREAD_COUNT, ITERATIONS]


def _text_syscall_names(workload):
    if workload == "scalar":
        return ("getpid", "clock_gettime")
    if workload == "small":
        return ("arch_prctl", "get_robust_list")
    return ("getpid",)


def _count_json_events(stderr, event_type):
    count = 0
    for line in stderr.splitlines():
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == event_type:
            count += 1
    return count


def _count_text_syscalls(stderr, syscall_names):
    return sum(
        1
        for line in stderr.splitlines()
        if any(f"{name}(" in line for name in syscall_names)
    )


def _run_capture(
    name, fixture, event_format, workload="threads", allow_reserve_fail=False
):
    args = _fixture_args(fixture, workload)
    start = time.monotonic()
    timeout = LONG_CAPTURE_TIMEOUT_SECONDS if workload == "long" else 60
    if event_format in ("none", "handler", "reader", "text"):
        result = run_strace_go_capture(args, event_format, timeout=timeout)
    else:
        result = run_strace_go_json(args, timeout=timeout, phases=True)
    return CaptureRun(
        name=name,
        result=result,
        elapsed=time.monotonic() - start,
        syscall_events=_count_json_events(result.stderr, "syscall"),
        ready_events=parse_ready_events(result.stderr),
        phase_events=parse_phase_events(result.stderr),
        stats_events=parse_stats_events(result.stderr),
        text_syscall_events=_count_text_syscalls(
            result.stderr, _text_syscall_names(workload)
        ),
        allow_reserve_fail=allow_reserve_fail,
    )


def _trace_seconds(capture):
    phases = {event.get("phase"): event for event in capture.phase_events}
    start = phases.get("trace_start", {}).get("time_ns", 0)
    end = phases.get("trace_end", {}).get("time_ns", 0)
    if start <= 0 or end <= start:
        return 0.0
    return (end - start) / 1_000_000_000


def _stats(capture):
    if len(capture.stats_events) != 1:
        return None
    stats = capture.stats_events[0]
    return stats if valid_stats_event(stats) else None


def _validate_capture(
    capture,
    expect_syscalls,
    expect_routed=False,
    minimum_text_syscalls=0,
    minimum_syscall_events=0,
):
    failures = []
    if capture.result.returncode != 0:
        failures.append(f"{capture.name} rc={capture.result.returncode}")
    if len(capture.ready_events) != 1:
        failures.append(f"{capture.name} ready events={len(capture.ready_events)}")
    if _trace_seconds(capture) <= 0:
        failures.append(f"{capture.name} trace phase is invalid")
    stats = _stats(capture)
    if stats is None:
        failures.append(f"{capture.name} stats event is missing or invalid")
    elif stats["records_read"] < stats["records_decoded"]:
        failures.append(f"{capture.name} decoded more records than read")
    elif stats["records_decoded"] < stats["records_routed"]:
        failures.append(f"{capture.name} routed more records than decoded")
    elif stats["records_invalid"] != stats["records_read"] - stats["records_decoded"]:
        failures.append(f"{capture.name} record accounting is inconsistent")
    if stats is not None:
        failures.extend(service_measurement_failures(stats, capture.name))
        if stats["producer_attempts_lower_bound"] < stats["records_read"]:
            failures.append(f"{capture.name} producer attempt lower bound is below records_read")
        diagnostics = (
            CAPTURE_PRESSURE_ZERO_DIAGNOSTICS
            if capture.allow_reserve_fail
            else CAPTURE_ZERO_DIAGNOSTICS
        )
        for key in diagnostics:
            if stats.get(key, 0) != 0:
                failures.append(f"{capture.name} {key}={stats.get(key)}")
    if expect_syscalls and capture.syscall_events == 0:
        failures.append(f"{capture.name} produced no syscall events")
    if minimum_syscall_events and capture.syscall_events < minimum_syscall_events:
        failures.append(
            f"{capture.name} syscall events={capture.syscall_events}, "
            f"want>={minimum_syscall_events}"
        )
    if expect_routed and stats is not None and stats["records_routed"] == 0:
        failures.append(f"{capture.name} routed no records")
    if capture.text_syscall_events < minimum_text_syscalls:
        failures.append(
            f"{capture.name} text syscall lines={capture.text_syscall_events}, "
            f"want at least {minimum_text_syscalls}"
        )
    if expect_syscalls and stats is not None:
        if stats["syscall_output_bytes"] <= 0:
            failures.append(f"{capture.name} syscall output bytes is zero")
        if stats["syscall_output_writes"] <= 0:
            failures.append(f"{capture.name} syscall output writes is zero")
        if stats["syscall_output_write_errors"] != 0:
            failures.append(
                f"{capture.name} syscall output write errors={stats['syscall_output_write_errors']}"
            )
        if stats["stage_enabled"]:
            if stats["state_records"] <= 0 or stats["dispatch_records"] <= 0:
                failures.append(f"{capture.name} sampled state/dispatch records are zero")
            if stats["syscall_write_time_samples"] <= 0:
                failures.append(f"{capture.name} sampled syscall write count is zero")
    if not expect_syscalls and capture.syscall_events != 0:
        failures.append(f"{capture.name} leaked {capture.syscall_events} syscall events")
    return failures, stats


def _print_capture(capture, stats):
    print(f"=== EBPF CAPTURE {capture.name} ===")
    print(f"returncode: {capture.result.returncode}")
    print(f"elapsed_sec: {capture.elapsed:.6f}")
    print(f"syscall_events: {capture.syscall_events}")
    print(f"text_syscall_events: {capture.text_syscall_events}")
    print(f"trace_sec: {_trace_seconds(capture):.6f}")
    if stats is None:
        print("stats: unavailable")
        return
    for field in (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
        "lifecycle_map_update_fail",
        "pending_stale",
        "records_read",
        "producer_attempts_lower_bound",
        "records_decoded",
        "records_invalid",
        "records_routed",
        "service_enabled",
        "service_sample_rate",
        "bytes_read",
        "max_record_bytes",
        "read_time_ns",
        "decode_time_ns",
        "sink_time_ns",
        "min_remaining_bytes",
        "service_time_ns",
        "service_records",
        "max_service_time_ns",
        "max_remaining_bytes",
        "syscall_output_bytes",
        "syscall_output_writes",
        "syscall_output_write_errors",
        "syscall_write_time_ns",
        "syscall_write_time_samples",
        "stage_enabled",
        "stage_sample_rate",
        "state_time_ns",
        "state_records",
        "max_state_time_ns",
        "dispatch_time_ns",
        "dispatch_records",
        "max_dispatch_time_ns",
    ):
        print(f"{field}: {stats.get(field)}")


def run_ebpf_capture(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_named_fixture(
        "strace-go-ebpf-capture-fixture", (PERF_FIXTURE_SRC,), ["-pthread"]
    )
    captures = (
        _run_capture("reader", fixture, "reader"),
        _run_capture("none", fixture, "none"),
        _run_capture("handler", fixture, "handler"),
        _run_capture("text", fixture, "text"),
        _run_capture("text-mixed", fixture, "text", workload="scalar"),
        _run_capture("text-small-struct", fixture, "text", workload="small"),
        _run_capture("json", fixture, "json"),
    )
    failed = False
    stats_by_name = {}
    for capture in captures:
        failures, stats = _validate_capture(
            capture,
            expect_syscalls=capture.name == "json",
            expect_routed=capture.name in ("text", "text-mixed", "text-small-struct"),
            minimum_text_syscalls=(
                2 * int(MIXED_ITERATIONS)
                if capture.name == "text-mixed"
                else 2 * int(SMALL_ITERATIONS)
                if capture.name == "text-small-struct"
                else 0
            ),
            minimum_syscall_events=(
                EXPECTED_JSON_SYSCALL_EVENTS if capture.name == "json" else 0
            ),
        )
        stats_by_name[capture.name] = stats
        _print_capture(capture, stats)
        for failure in failures:
            failed = True
            print(f"FAIL: {failure}")

    none_stats = stats_by_name.get("none")
    json_stats = stats_by_name.get("json")
    if none_stats is not None and json_stats is not None:
        print(
            "reserve_fail_delta_json_minus_none: "
            f"{json_stats['ringbuf_reserve_fail'] - none_stats['ringbuf_reserve_fail']}"
        )
    reader_stats = stats_by_name.get("reader")
    if none_stats is not None and reader_stats is not None:
        print(
            "records_read_delta_reader_minus_none: "
            f"{reader_stats['records_read'] - none_stats['records_read']}"
        )
    if failed:
        return 1
    print("PASS: ebpf-capture")
    return 0


def _validate_long_capture(capture):
    failures, stats = _validate_capture(capture, expect_syscalls=False)
    if stats is None:
        return failures, stats
    if stats["producer_attempts_lower_bound"] < MIN_LONG_PRODUCER_ATTEMPTS:
        failures.append(
            f"{capture.name} producer attempts={stats['producer_attempts_lower_bound']}, "
            f"want>={MIN_LONG_PRODUCER_ATTEMPTS}"
        )
    if stats["producer_attempts_lower_bound"] != (
        stats["records_read"] + stats["ringbuf_reserve_fail"]
    ):
        failures.append(f"{capture.name} producer/read/drop accounting is inconsistent")
    if stats["records_invalid"] != 0:
        failures.append(f"{capture.name} records_invalid={stats['records_invalid']}")
    return failures, stats


def _print_long_capture(capture, stats):
    print(f"=== EBPF CAPTURE LONG {capture.name} ===")
    print(f"returncode: {capture.result.returncode}")
    print(f"trace_sec: {_trace_seconds(capture):.6f}")
    if stats is None:
        print("stats: unavailable")
        return
    attempts = stats["producer_attempts_lower_bound"]
    reserve_fail = stats["ringbuf_reserve_fail"]
    loss_rate = reserve_fail / attempts if attempts else 0.0
    print(f"producer_attempts_lower_bound: {attempts}")
    print(f"records_read: {stats['records_read']}")
    print(f"records_decoded: {stats['records_decoded']}")
    print(f"records_invalid: {stats['records_invalid']}")
    print(f"ringbuf_reserve_fail: {reserve_fail}")
    print(f"ringbuf_reserve_loss_rate: {loss_rate:.6%}")
    print(f"ringbuf_copy_fail: {stats['ringbuf_copy_fail']}")
    print(f"pending_update_fail: {stats['pending_update_fail']}")
    print(f"orphan_exit: {stats['orphan_exit']}")
    print(f"pending_mismatch: {stats['pending_mismatch']}")
    print(f"lifecycle_map_update_fail: {stats['lifecycle_map_update_fail']}")
    print(f"pending_stale: {stats['pending_stale']}")


def run_ebpf_capture_long(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_named_fixture(
        "strace-go-ebpf-long-capture-fixture", (PERF_FIXTURE_SRC,), ["-pthread"]
    )
    captures = (
        _run_capture("long-none", fixture, "none", "long", True),
        _run_capture("long-reader", fixture, "reader", "long", True),
    )
    failed = False
    for capture in captures:
        failures, stats = _validate_long_capture(capture)
        _print_long_capture(capture, stats)
        for failure in failures:
            failed = True
            print(f"FAIL: {failure}")
    if failed:
        return 1
    print("PASS: ebpf-capture-long")
    return 0
