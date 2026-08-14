#!/usr/bin/env python3
import subprocess
import unittest

from ebpf_perf_suite import (
    PerfCapture,
    PerfWorkloadSpec,
    parse_go_benchmark_metrics,
    validate_perf_capture,
)


def make_capture(events=None, lifecycle_events=None, stats=None, returncode=0):
    zero_stats = {
        "available": True,
        "ringbuf_reserve_fail": 0,
        "ringbuf_copy_fail": 0,
        "payload_truncated_events": 0,
        "pending_update_fail": 0,
        "orphan_exit": 0,
        "pending_mismatch": 0,
        "lifecycle_map_update_fail": 0,
        "pending_stale": 0,
    }
    if stats:
        zero_stats.update(stats)
    return PerfCapture(
        name="unit",
        result=subprocess.CompletedProcess([], returncode, "", ""),
        elapsed=0.1,
        events=events or [],
        lifecycle_events=lifecycle_events or [],
        stats_events=[zero_stats],
        ready_events=[{"type": "ready", "start_time_ns": 100, "time_ns": 150}],
        phase_events=[
            {"type": "phase", "phase": "bpf_memlock", "start_time_ns": 100, "time_ns": 110},
            {"type": "phase", "phase": "bpf_spec", "start_time_ns": 110, "time_ns": 120},
            {"type": "phase", "phase": "bpf_route_plan", "start_time_ns": 120, "time_ns": 125},
            {"type": "phase", "phase": "bpf_object_prepare", "start_time_ns": 125, "time_ns": 127},
            {"type": "phase", "phase": "bpf_core_collection_load", "start_time_ns": 127, "time_ns": 130},
            {"type": "phase", "phase": "bpf_enter_collection_load", "start_time_ns": 130, "time_ns": 132},
            {"type": "phase", "phase": "bpf_exit_collection_load", "start_time_ns": 132, "time_ns": 134},
            {"type": "phase", "phase": "bpf_recvmsg_collection_load", "start_time_ns": 134, "time_ns": 136},
            {"type": "phase", "phase": "bpf_resource_bind", "start_time_ns": 136, "time_ns": 138},
            {"type": "phase", "phase": "bpf_route_maps", "start_time_ns": 138, "time_ns": 140},
            {"type": "phase", "phase": "bpf_prog_arrays", "start_time_ns": 140, "time_ns": 142},
            {"type": "phase", "phase": "bpf_tracepoints", "start_time_ns": 142, "time_ns": 145},
            {"type": "phase", "phase": "bpf_recvmsg_kretprobe", "start_time_ns": 145, "time_ns": 148},
            {"type": "phase", "phase": "trace_start", "time_ns": 200},
            {"type": "phase", "phase": "trace_end", "time_ns": 300},
            {"type": "phase", "phase": "finalize_start", "time_ns": 301},
        ],
    )


class PerfOracleTests(unittest.TestCase):
    def test_parses_go_benchmark_allocation_metrics(self):
        output = (
            "BenchmarkTraceEventDecodeState-8  1000  123.4 ns/op  96 B/op  2 allocs/op\n"
            "BenchmarkJSONEventWriter-8  500  456.7 ns/op  128 B/op  3 allocs/op\n"
            "BenchmarkJSONDecodedEventWriter-8  500  600.7 ns/op  160 B/op  4 allocs/op\n"
            "BenchmarkJSONDecodedPayloadEventWriter-8  500  900.7 ns/op  320 B/op  6 allocs/op\n"
        )

        metrics = parse_go_benchmark_metrics(output)

        self.assertEqual(
            metrics,
            [
                {
                    "name": "BenchmarkTraceEventDecodeState-8",
                    "ns_per_op": 123.4,
                    "bytes_per_op": 96.0,
                    "allocs_per_op": 2.0,
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
            ],
        )

    def test_rejects_go_benchmark_without_alloc_metrics(self):
        output = "BenchmarkTraceEventDecodeState-8  1000  123.4 ns/op\n"

        self.assertEqual(parse_go_benchmark_metrics(output), [])

    def test_rejects_missing_nested_io_payload(self):
        spec = PerfWorkloadSpec(
            name="io",
            minimum_exit_counts=(('read', 1), ('write', 1)),
            payload_requirements=(('read', 'out', 1), ('write', 'in', 1)),
        )
        events = [
            {"syscall": "read", "event_type": "exit", "paired_enter": True},
            {"syscall": "write", "event_type": "exit", "paired_enter": True},
        ]

        failures = validate_perf_capture(make_capture(events=events), spec)

        self.assertTrue(any("payload" in failure for failure in failures))

    def test_rejects_unpaired_exit(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        events = [{"syscall": "getpid", "event_type": "exit", "paired_enter": False}]

        failures = validate_perf_capture(make_capture(events=events), spec)

        self.assertTrue(any("paired" in failure for failure in failures))

    def test_rejects_runtime_error_counter(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        events = [{"syscall": "getpid", "event_type": "exit", "paired_enter": True}]

        failures = validate_perf_capture(
            make_capture(events=events, stats={"ringbuf_reserve_fail": 1}), spec
        )

        self.assertTrue(any("ringbuf_reserve_fail" in failure for failure in failures))

    def test_rejects_stale_pending_state(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        events = [{"syscall": "getpid", "event_type": "exit", "paired_enter": True}]

        failures = validate_perf_capture(
            make_capture(events=events, stats={"pending_stale": 1}), spec
        )

        self.assertTrue(any("pending_stale" in failure for failure in failures))

    def test_rejects_missing_lifecycle_action(self):
        spec = PerfWorkloadSpec(
            name="lifecycle",
            minimum_exit_counts=(('execve', 1),),
            lifecycle_actions=('fork', 'exec', 'exit'),
        )
        events = [{"syscall": "execve", "event_type": "exit", "paired_enter": True}]

        failures = validate_perf_capture(
            make_capture(events=events, lifecycle_events=[{"action": "fork"}]), spec
        )

        self.assertTrue(any("lifecycle exec" in failure for failure in failures))

    def test_accepts_non_leader_thread_pairing(self):
        spec = PerfWorkloadSpec(
            name="threads",
            minimum_exit_counts=(('getpid', 1),),
            require_non_leader_tid=True,
        )
        events = [
            {"syscall": "getpid", "event_type": "enter", "pid": 10, "tid": 11},
            {
                "syscall": "getpid",
                "event_type": "exit",
                "pid": 10,
                "tid": 11,
                "paired_enter": True,
            },
        ]

        failures = validate_perf_capture(make_capture(events=events), spec)

        self.assertEqual(failures, [])

    def test_rejects_missing_perf_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events = [
            {"type": "phase", "phase": "trace_start", "time_ns": 200},
        ]

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("phase" in failure for failure in failures))

    def test_rejects_missing_bpf_setup_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events = [
            event
            for event in capture.phase_events
            if event.get("phase") != "bpf_core_collection_load"
        ]

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("BPF setup" in failure for failure in failures))

    def test_rejects_non_monotonic_perf_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events = [
            {"type": "phase", "phase": "trace_start", "time_ns": 300},
            {"type": "phase", "phase": "trace_end", "time_ns": 200},
            {"type": "phase", "phase": "finalize_start", "time_ns": 201},
        ]

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("phase" in failure for failure in failures))

    def test_rejects_duplicate_perf_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events.append(
            {"type": "phase", "phase": "trace_end", "time_ns": 302}
        )

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("duplicate" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
