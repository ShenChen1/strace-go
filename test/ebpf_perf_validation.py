#!/usr/bin/env python3
import re

from ebpf_check_support import service_measurement_failures, valid_stats_event
from ebpf_perf_model import (
    REQUIRED_BPF_SETUP_PHASES,
    REQUIRED_PERF_PHASES,
    RUNTIME_DIAGNOSTIC_FIELDS,
)
from ebpf_perf_phases import (
    REQUIRED_BPF_CLEANUP_PHASES,
    REQUIRED_CLEANUP_PHASES,
    cleanup_phase_durations,
    validate_cleanup_phases,
)


GO_BENCHMARK_PATTERN = re.compile(
    r"^(?P<name>Benchmark\S+)\s+\d+\s+"
    r"(?P<ns>[0-9]+(?:\.[0-9]+)?)\s+ns/op\s+"
    r"(?P<bytes>[0-9]+(?:\.[0-9]+)?)\s+B/op\s+"
    r"(?P<allocs>[0-9]+(?:\.[0-9]+)?)\s+allocs/op(?:\s+.*)?$"
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


def _validate_phase_timing(capture):
    failures = []
    if len(capture.ready_events) != 1:
        failures.append(f"{capture.name} ready event count={len(capture.ready_events)}")
        return failures
    ready = capture.ready_events[0]
    start_time = ready.get("start_time_ns", 0)
    ready_time = ready.get("time_ns", 0)
    if start_time <= 0 or ready_time < start_time:
        failures.append(f"{capture.name} ready phase timing is invalid")

    phase_counts = {}
    for event in capture.phase_events:
        phase = event.get("phase")
        phase_counts[phase] = phase_counts.get(phase, 0) + 1
    duplicates = [phase for phase, count in phase_counts.items() if count > 1]
    if duplicates:
        failures.append(
            f"{capture.name} duplicate phase events: {','.join(map(str, duplicates))}"
        )
    phases = {event.get("phase"): event for event in capture.phase_events}
    failures.extend(_validate_bpf_setup_phases(capture, phases, start_time, ready_time))
    missing = [phase for phase in REQUIRED_PERF_PHASES if phase not in phases]
    if missing:
        failures.append(f"{capture.name} missing phase events: {','.join(missing)}")
        return failures
    phase_times = [phases[phase].get("time_ns", 0) for phase in REQUIRED_PERF_PHASES]
    if any(time_ns <= 0 for time_ns in phase_times) or phase_times != sorted(phase_times):
        failures.append(f"{capture.name} phase timing is not monotonic")
    if phase_times[0] < ready_time:
        failures.append(f"{capture.name} trace started before ready")
    failures.extend(validate_cleanup_phases(phases, capture.name))
    return failures


def _validate_bpf_setup_phases(capture, phases, start_time, ready_time):
    failures = []
    missing = [phase for phase in REQUIRED_BPF_SETUP_PHASES if phase not in phases]
    if missing:
        failures.append(
            f"{capture.name} missing BPF setup phases: {','.join(missing)}"
        )
    for phase in REQUIRED_BPF_SETUP_PHASES:
        event = phases.get(phase)
        if event is None:
            continue
        phase_start = event.get("start_time_ns", 0)
        phase_end = event.get("time_ns", 0)
        if phase_start <= 0 or phase_end < phase_start:
            failures.append(f"{capture.name} {phase} timing is invalid")
        if phase_start < start_time or phase_end > ready_time:
            failures.append(f"{capture.name} {phase} is outside BPF setup")
    first_bpf = phases.get(REQUIRED_BPF_SETUP_PHASES[0])
    if first_bpf is not None and first_bpf.get("start_time_ns", 0) < start_time:
        failures.append(f"{capture.name} BPF setup starts before bootstrap")
    return failures


def _phase_interval_union_seconds(phases, phase_names):
    intervals = []
    for phase in phase_names:
        event = phases.get(phase)
        if event is None:
            continue
        start_time_ns = event.get("start_time_ns", 0)
        end_time_ns = event.get("time_ns", 0)
        if end_time_ns >= start_time_ns:
            intervals.append((start_time_ns, end_time_ns))
    intervals.sort()
    total_ns = 0
    current_start = current_end = None
    for start_time_ns, end_time_ns in intervals:
        if current_start is None:
            current_start, current_end = start_time_ns, end_time_ns
            continue
        if start_time_ns > current_end:
            total_ns += current_end - current_start
            current_start, current_end = start_time_ns, end_time_ns
        else:
            current_end = max(current_end, end_time_ns)
    if current_start is not None:
        total_ns += current_end - current_start
    return total_ns / 1_000_000_000


def phase_durations(capture):
    if len(capture.ready_events) != 1:
        return None
    phases = {event.get("phase"): event for event in capture.phase_events}
    required = (
        *REQUIRED_BPF_SETUP_PHASES,
        *REQUIRED_PERF_PHASES,
        *REQUIRED_CLEANUP_PHASES,
        *REQUIRED_BPF_CLEANUP_PHASES,
    )
    if any(phase not in phases for phase in required):
        return None
    ready = capture.ready_events[0]
    try:
        ready_time = ready["time_ns"]
        start_time = ready["start_time_ns"]
        trace_start = phases["trace_start"]["time_ns"]
        trace_end = phases["trace_end"]["time_ns"]
        finalize_start = phases["finalize_start"]["time_ns"]
        cleanup_start = phases["cleanup_start"]["time_ns"]
        bpf_durations = {
            f"{phase}_sec": (
                phases[phase]["time_ns"] - phases[phase]["start_time_ns"]
            )
            / 1_000_000_000
            for phase in REQUIRED_BPF_SETUP_PHASES
        }
    except (KeyError, TypeError):
        return None
    durations = {
        "setup_sec": (ready_time - start_time) / 1_000_000_000,
        "trace_sec": (trace_end - trace_start) / 1_000_000_000,
        "finalize_start_sec": (finalize_start - trace_end) / 1_000_000_000,
        "cleanup_sec": (cleanup_start - finalize_start) / 1_000_000_000,
        "post_cleanup_unattributed_sec": capture.elapsed
        - (cleanup_start - start_time) / 1_000_000_000,
    }
    durations.update(cleanup_phase_durations(phases))
    durations.update(bpf_durations)
    durations["bpf_setup_sec"] = _phase_interval_union_seconds(
        phases, REQUIRED_BPF_SETUP_PHASES
    )
    return durations


def _validate_runtime(capture, spec, stats):
    failures = []
    if capture.result.returncode != 0:
        failures.append(f"{spec.name} fixture rc={capture.result.returncode}")
    if len(capture.stats_events) != 1:
        failures.append(f"{spec.name} stats event count={len(capture.stats_events)}")
    if not valid_stats_event(stats):
        failures.append(f"{spec.name} stats event is invalid")
    failures.extend(_validate_phase_timing(capture))
    failures.extend(service_measurement_failures(stats, spec.name))
    if stats.get("producer_attempts_lower_bound", 0) < stats.get("records_read", 0):
        failures.append(
            f"{spec.name} producer_attempts_lower_bound="
            f"{stats.get('producer_attempts_lower_bound')} is below "
            f"records_read={stats.get('records_read')}"
        )
    for counter in RUNTIME_DIAGNOSTIC_FIELDS:
        if stats.get(counter, 1) != 0:
            failures.append(f"{spec.name} {counter}={stats.get(counter)}")
    return failures


def _validate_record_limits(capture, spec, stats):
    failures = []
    if spec.max_bytes_read and stats.get("bytes_read", 0) > spec.max_bytes_read:
        failures.append(
            f"{spec.name} bytes_read={stats.get('bytes_read')}, "
            f"want<={spec.max_bytes_read}"
        )
    if spec.minimum_records_read and stats.get("records_read", 0) < spec.minimum_records_read:
        failures.append(
            f"{spec.name} records_read={stats.get('records_read')}, "
            f"want>={spec.minimum_records_read}"
        )
    if (
        spec.minimum_producer_attempts_lower_bound
        and stats.get("producer_attempts_lower_bound", 0)
        < spec.minimum_producer_attempts_lower_bound
    ):
        failures.append(
            f"{spec.name} producer_attempts_lower_bound="
            f"{stats.get('producer_attempts_lower_bound')}, "
            f"want>={spec.minimum_producer_attempts_lower_bound}"
        )
    return failures


def _validate_syscalls(capture, spec):
    failures = []
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
    if spec.require_non_leader_tid and not any(
        event.get("event_type") == "exit" and event.get("tid") != event.get("pid")
        for event in capture.events
    ):
        failures.append(f"{spec.name} non-leader TID event missing")
    return failures


def _validate_lifecycle(capture, spec, stats):
    failures = []
    for action in spec.lifecycle_actions:
        if not any(event.get("action") == action for event in capture.lifecycle_events):
            failures.append(f"{spec.name} lifecycle {action} missing")
    for action, minimum in spec.lifecycle_minimum_counts:
        actual = sum(
            1 for event in capture.lifecycle_events if event.get("action") == action
        )
        if actual < minimum:
            failures.append(f"{spec.name} lifecycle {action}={actual}, want>={minimum}")
    for field, minimum in spec.lifecycle_stat_minimums:
        actual = stats.get(field, -1)
        if actual < minimum:
            failures.append(f"{spec.name} {field}={actual}, want>={minimum}")
    for field in spec.lifecycle_stat_zeroes:
        actual = stats.get(field, -1)
        if actual != 0:
            failures.append(f"{spec.name} {field}={actual}, want=0")
    return failures


def validate_perf_capture(capture, spec):
    stats = capture.stats_events[0] if capture.stats_events else {}
    failures = _validate_runtime(capture, spec, stats)
    failures.extend(_validate_record_limits(capture, spec, stats))
    failures.extend(_validate_syscalls(capture, spec))
    failures.extend(_validate_lifecycle(capture, spec, stats))
    return failures
