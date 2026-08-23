#!/usr/bin/env python3

from ebpf_perf_model import (
    REQUIRED_BPF_SETUP_PHASES,
    RUNTIME_DIAGNOSTIC_FIELDS,
)
from ebpf_perf_phases import REQUIRED_BPF_CLEANUP_PHASES, REQUIRED_CLEANUP_PHASES
from ebpf_perf_validation import phase_durations


LIFECYCLE_FIELDS = (
    "lifecycle_fork_seen",
    "lifecycle_fork_parent_tracked",
    "lifecycle_fork_parent_untracked",
    "lifecycle_fork_child_filter_installed",
    "lifecycle_fork_child_filter_failed",
    "lifecycle_exec_seen",
    "lifecycle_exec_untracked",
    "lifecycle_exit_seen",
    "lifecycle_exit_untracked",
)
SERVICE_FIELDS = (
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
    "stage_enabled",
    "stage_sample_rate",
    "state_time_ns",
    "state_records",
    "max_state_time_ns",
    "dispatch_time_ns",
    "dispatch_records",
    "max_dispatch_time_ns",
    "syscall_write_time_ns",
    "syscall_write_time_samples",
)


def _print_capture_header(capture):
    print(f"=== EBPF PERF {capture.name} ===")
    print(f"returncode: {capture.result.returncode}")
    print(f"elapsed_sec: {capture.elapsed:.6f}")
    print(f"json_events: {len(capture.events)}")
    print(f"exit_events: {len(capture.exit_events)}")
    print(f"lifecycle_events: {len(capture.lifecycle_events)}")
    print(f"ready_events: {len(capture.ready_events)}")
    print(f"phase_events: {len(capture.phase_events)}")


def _print_stat_fields(stats):
    for field in RUNTIME_DIAGNOSTIC_FIELDS:
        print(f"{field}: {stats.get(field)}")
    for field in LIFECYCLE_FIELDS:
        print(f"{field}: {stats.get(field)}")
    for field in SERVICE_FIELDS:
        print(f"{field}: {stats.get(field)}")
    if stats.get("service_records", 0) > 0:
        print(
            "consumer_service_ns_per_sample: "
            f"{stats.get('service_time_ns', 0) / stats['service_records']:.2f}"
        )


def _print_phase_fields(capture):
    durations = phase_durations(capture)
    if durations is None:
        return
    print(f"setup_sec: {durations['setup_sec']:.6f}")
    print(f"bpf_setup_sec: {durations['bpf_setup_sec']:.6f}")
    for phase in REQUIRED_BPF_SETUP_PHASES:
        print(f"{phase}_sec: {durations[f'{phase}_sec']:.6f}")
    print(f"trace_sec: {durations['trace_sec']:.6f}")
    print(f"finalize_start_delay_sec: {durations['finalize_start_sec']:.6f}")
    print(f"cleanup_sec: {durations['cleanup_sec']:.6f}")
    print(f"cleanup_owner_sec: {durations['cleanup_owner_sec']:.6f}")
    for phase in REQUIRED_CLEANUP_PHASES:
        print(f"{phase}_sec: {durations[f'{phase}_sec']:.6f}")
    for phase in REQUIRED_BPF_CLEANUP_PHASES:
        print(f"{phase}_sec: {durations[f'{phase}_sec']:.6f}")
    print(
        "post_cleanup_unattributed_sec: "
        f"{durations['post_cleanup_unattributed_sec']:.6f}"
    )
    if durations["trace_sec"] > 0:
        print(
            "trace_exit_events_per_sec: "
            f"{len(capture.exit_events) / durations['trace_sec']:.2f}"
        )
    print(
        "unattributed_sec: "
        f"{capture.elapsed - durations['setup_sec'] - durations['trace_sec']:.6f}"
    )


def print_perf_capture(capture):
    stats = capture.stats_events[0] if capture.stats_events else {}
    _print_capture_header(capture)
    _print_stat_fields(stats)
    if capture.elapsed > 0:
        print(
            "end_to_end_exit_events_per_sec: "
            f"{len(capture.exit_events) / capture.elapsed:.2f}"
        )
    _print_phase_fields(capture)


def print_go_pipeline_benchmarks(result, metrics):
    print("=== GO PERF event-pipeline ===")
    print(f"returncode: {result.returncode}")
    for metric in metrics:
        print(
            f"{metric['name']}: ns/op={metric['ns_per_op']:.2f} "
            f"B/op={metric['bytes_per_op']:.2f} "
            f"allocs/op={metric['allocs_per_op']:.2f}"
        )
