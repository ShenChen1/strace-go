#!/usr/bin/env python3
import subprocess

from ebpf_perf_model import PerfCapture


def _base_stats():
    return {
        "available": True,
        "ringbuf_reserve_fail": 0,
        "ringbuf_copy_fail": 0,
        "payload_truncated_events": 0,
        "pending_update_fail": 0,
        "orphan_exit": 0,
        "pending_mismatch": 0,
        "lifecycle_map_update_fail": 0,
        "lifecycle_fork_seen": 0,
        "lifecycle_fork_parent_tracked": 0,
        "lifecycle_fork_parent_untracked": 0,
        "lifecycle_fork_child_filter_installed": 0,
        "lifecycle_fork_child_filter_failed": 0,
        "lifecycle_exec_seen": 0,
        "lifecycle_exec_untracked": 0,
        "lifecycle_exit_seen": 0,
        "lifecycle_exit_untracked": 0,
        "pending_stale": 0,
        "records_read": 1,
        "producer_attempts_lower_bound": 1,
        "records_decoded": 1,
        "records_invalid": 0,
        "records_routed": 1,
        "service_enabled": True,
        "service_sample_rate": 1,
        "bytes_read": 96,
        "max_record_bytes": 96,
        "read_time_ns": 10,
        "decode_time_ns": 40,
        "sink_time_ns": 60,
        "min_remaining_bytes": 64,
        "service_time_ns": 100,
        "service_records": 1,
        "max_service_time_ns": 100,
        "max_remaining_bytes": 128,
        "syscall_output_bytes": 0,
        "syscall_output_writes": 0,
        "syscall_output_write_errors": 0,
        "syscall_write_time_ns": 0,
        "syscall_write_time_samples": 0,
        "stage_enabled": True,
        "stage_sample_rate": 1,
        "state_time_ns": 0,
        "state_records": 0,
        "max_state_time_ns": 0,
        "dispatch_time_ns": 0,
        "dispatch_records": 0,
        "max_dispatch_time_ns": 0,
    }


def _phase_events():
    setup = [
        ("bpf_memlock", 100, 110),
        ("bpf_spec", 110, 120),
        ("bpf_route_plan", 120, 125),
        ("bpf_object_prepare", 125, 127),
        ("bpf_core_collection_load", 127, 130),
        ("bpf_handler_collections_load", 130, 146),
        ("bpf_enter_generic_collection_load", 130, 132),
        ("bpf_enter_payload_collection_load", 130, 134),
        ("bpf_enter_path_collection_load", 130, 136),
        ("bpf_enter_memory_collection_load", 130, 138),
        ("bpf_enter_control_collection_load", 130, 140),
        ("bpf_enter_structured_collection_load", 130, 142),
        ("bpf_exit_collection_load", 130, 144),
        ("bpf_recvmsg_collection_load", 130, 146),
        ("bpf_resource_bind", 146, 148),
        ("bpf_route_maps", 148, 150),
        ("bpf_prog_arrays", 150, 152),
        ("bpf_tracepoints", 152, 155),
        ("bpf_recvmsg_kretprobe", 155, 158),
    ]
    phases = [
        {"type": "phase", "phase": name, "start_time_ns": start, "time_ns": end}
        for name, start, end in setup
    ]
    phases.extend(
        [
            {"type": "phase", "phase": "trace_start", "time_ns": 200},
            {"type": "phase", "phase": "trace_end", "time_ns": 300},
            {"type": "phase", "phase": "finalize_start", "time_ns": 301},
            {"type": "phase", "phase": "cleanup_start", "time_ns": 302},
        ]
    )
    cleanup = (
        "cleanup_output",
        "cleanup_target_handoff",
        "cleanup_target_bootstrap",
        "cleanup_ringbuf_reader",
    )
    phases.extend(
        {
            "type": "phase",
            "phase": name,
            "start_time_ns": 303 + index,
            "time_ns": 304 + index,
        }
        for index, name in enumerate(cleanup)
    )
    phases.extend(
        [
            {"type": "phase", "phase": "cleanup_bpf_links", "start_time_ns": 307, "time_ns": 307},
            {"type": "phase", "phase": "cleanup_bpf_core_objects", "start_time_ns": 307, "time_ns": 307},
            {"type": "phase", "phase": "cleanup_bpf_runtime", "start_time_ns": 307, "time_ns": 308},
        ]
    )
    return phases


def make_capture(events=None, lifecycle_events=None, stats=None, returncode=0):
    base_stats = _base_stats()
    if stats:
        base_stats.update(stats)
    return PerfCapture(
        name="unit",
        result=subprocess.CompletedProcess([], returncode, "", ""),
        elapsed=0.1,
        events=events or [],
        lifecycle_events=lifecycle_events or [],
        stats_events=[base_stats],
        ready_events=[{"type": "ready", "start_time_ns": 100, "time_ns": 170}],
        phase_events=_phase_events(),
    )


def expected_benchmark_metrics():
    return [
        {
            "name": "BenchmarkTraceRecordDecoderPayload-8",
            "ns_per_op": 100.4,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkTraceEventDecodeState-8",
            "ns_per_op": 123.4,
            "bytes_per_op": 96.0,
            "allocs_per_op": 2.0,
        },
        {
            "name": "BenchmarkTraceStateDeferredPayload-8",
            "ns_per_op": 200.4,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkTraceEventContextHandler-8",
            "ns_per_op": 234.5,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkTraceEventHandlerPipeline-8",
            "ns_per_op": 345.6,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkTraceEventTextPipeline-8",
            "ns_per_op": 456.7,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkTraceEventJSONPipeline-8",
            "ns_per_op": 567.8,
            "bytes_per_op": 0.0,
            "allocs_per_op": 0.0,
        },
        {
            "name": "BenchmarkJSONEventWriter-8",
            "ns_per_op": 456.7,
            "bytes_per_op": 128.0,
            "allocs_per_op": 3.0,
        },
        {
            "name": "BenchmarkJSONDecodedEventWriter-8",
            "ns_per_op": 600.7,
            "bytes_per_op": 160.0,
            "allocs_per_op": 4.0,
        },
        {
            "name": "BenchmarkJSONDecodedPayloadEventWriter-8",
            "ns_per_op": 900.7,
            "bytes_per_op": 320.0,
            "allocs_per_op": 6.0,
        },
    ]
