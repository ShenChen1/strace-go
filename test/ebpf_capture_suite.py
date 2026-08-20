#!/usr/bin/env python3
import json
import os
import time
from dataclasses import dataclass

from ebpf_check_support import valid_stats_event
from ebpf_event_oracles import (
    parse_phase_events,
    parse_ready_events,
    parse_stats_events,
)
from ebpf_fixture_build import build_named_fixture
from ebpf_suites import build_strace_go, run_strace_go_json, run_strace_go_none


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PERF_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_perf_fixture.c")
THREAD_COUNT = "16"
ITERATIONS = "100000"


@dataclass
class CaptureRun:
    name: str
    result: object
    elapsed: float
    syscall_events: int
    ready_events: list
    phase_events: list
    stats_events: list


def _fixture_args(fixture):
    return ["-f", "-e", "trace=getpid", fixture, "threads", THREAD_COUNT, ITERATIONS]


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


def _run_capture(name, fixture, discard_mode):
    args = _fixture_args(fixture)
    start = time.monotonic()
    if discard_mode:
        result = run_strace_go_none(args, timeout=60)
    else:
        result = run_strace_go_json(args, timeout=60, phases=True)
    return CaptureRun(
        name=name,
        result=result,
        elapsed=time.monotonic() - start,
        syscall_events=_count_json_events(result.stderr, "syscall"),
        ready_events=parse_ready_events(result.stderr),
        phase_events=parse_phase_events(result.stderr),
        stats_events=parse_stats_events(result.stderr),
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


def _validate_capture(capture, expect_syscalls):
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
    if expect_syscalls and capture.syscall_events == 0:
        failures.append(f"{capture.name} produced no syscall events")
    if not expect_syscalls and capture.syscall_events != 0:
        failures.append(f"{capture.name} leaked {capture.syscall_events} syscall events")
    return failures, stats


def _print_capture(capture, stats):
    print(f"=== EBPF CAPTURE {capture.name} ===")
    print(f"returncode: {capture.result.returncode}")
    print(f"elapsed_sec: {capture.elapsed:.6f}")
    print(f"syscall_events: {capture.syscall_events}")
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
        "records_decoded",
        "records_invalid",
        "records_routed",
        "max_remaining_bytes",
    ):
        print(f"{field}: {stats.get(field)}")


def run_ebpf_capture(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_named_fixture(
        "strace-go-ebpf-capture-fixture", (PERF_FIXTURE_SRC,), ["-pthread"]
    )
    captures = (
        _run_capture("none", fixture, True),
        _run_capture("json", fixture, False),
    )
    failed = False
    stats_by_name = {}
    for capture in captures:
        failures, stats = _validate_capture(
            capture, expect_syscalls=capture.name == "json"
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
    if failed:
        return 1
    print("PASS: ebpf-capture")
    return 0
