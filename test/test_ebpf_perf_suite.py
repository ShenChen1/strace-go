#!/usr/bin/env python3
import io
import subprocess
import unittest
from contextlib import redirect_stdout

from ebpf_perf_suite import (
    PerfCapture,
    PerfWorkloadSpec,
    parse_go_benchmark_metrics,
    print_perf_capture,
    validate_perf_capture,
)
from ebpf_perf_testdata import expected_benchmark_metrics, make_capture


class PerfOracleTests(unittest.TestCase):
    def test_prints_explicit_exit_event_rate_boundaries(self):
        capture = make_capture(
            events=[
                {
                    "syscall": "getpid",
                    "event_type": "exit",
                    "paired_enter": True,
                }
            ],
        )
        output = io.StringIO()

        with redirect_stdout(output):
            print_perf_capture(capture)

        text = output.getvalue()
        self.assertIn("end_to_end_exit_events_per_sec:", text)
        self.assertIn("trace_exit_events_per_sec:", text)
        self.assertNotIn("\nevents_per_sec:", text)
        self.assertNotIn("steady_state_events_per_sec:", text)

    def test_parses_go_benchmark_allocation_metrics(self):
        output = (
            "BenchmarkTraceRecordDecoderPayload-8  1000  100.4 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkTraceEventDecodeState-8  1000  123.4 ns/op  96 B/op  2 allocs/op\n"
            "BenchmarkTraceStateDeferredPayload-8  1000  200.4 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkTraceEventContextHandler-8  1000  234.5 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkTraceEventHandlerPipeline-8  1000  345.6 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkTraceEventTextPipeline-8  1000  456.7 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkTraceEventJSONPipeline-8  1000  567.8 ns/op  0 B/op  0 allocs/op\n"
            "BenchmarkJSONEventWriter-8  500  456.7 ns/op  128 B/op  3 allocs/op\n"
            "BenchmarkJSONDecodedEventWriter-8  500  600.7 ns/op  160 B/op  4 allocs/op\n"
            "BenchmarkJSONDecodedPayloadEventWriter-8  500  900.7 ns/op  320 B/op  6 allocs/op\n"
        )

        metrics = parse_go_benchmark_metrics(output)

        self.assertEqual(metrics, expected_benchmark_metrics())

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

    def test_rejects_io_payload_byte_budget_regression(self):
        spec = PerfWorkloadSpec(
            name="io",
            minimum_exit_counts=(("read", 1), ("write", 1)),
            max_bytes_read=900000,
        )
        events = [
            {"syscall": "read", "event_type": "exit", "paired_enter": True},
            {"syscall": "write", "event_type": "exit", "paired_enter": True},
        ]

        failures = validate_perf_capture(
            make_capture(events=events, stats={"bytes_read": 900001}), spec
        )

        self.assertTrue(any("bytes_read" in failure for failure in failures))

    def test_accepts_long_reader_record_and_bytes_budget(self):
        spec = PerfWorkloadSpec(
            name="io-long-reader",
            minimum_exit_counts=(),
            event_format="reader",
            max_bytes_read=65000000,
            minimum_records_read=400000,
            minimum_producer_attempts_lower_bound=400000,
        )

        failures = validate_perf_capture(
            make_capture(
                stats={
                    "records_read": 400005,
                    "producer_attempts_lower_bound": 400005,
                    "bytes_read": 63205136,
                }
            ),
            spec,
        )

        self.assertEqual(failures, [])

    def test_rejects_long_reader_record_budget_regression(self):
        spec = PerfWorkloadSpec(
            name="io-long-reader",
            minimum_exit_counts=(),
            event_format="reader",
            minimum_records_read=400000,
            minimum_producer_attempts_lower_bound=400000,
        )

        failures = validate_perf_capture(
            make_capture(
                stats={
                    "records_read": 399999,
                    "producer_attempts_lower_bound": 399999,
                }
            ),
            spec,
        )

        self.assertTrue(any("records_read" in failure for failure in failures))

    def test_rejects_producer_accounting_below_records_read(self):
        spec = PerfWorkloadSpec(name="io-long-reader", minimum_exit_counts=())

        failures = validate_perf_capture(
            make_capture(
                stats={
                    "records_read": 10,
                    "producer_attempts_lower_bound": 9,
                }
            ),
            spec,
        )

        self.assertTrue(any("below records_read" in failure for failure in failures))

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

    def test_accepts_lifecycle_storm_counts_and_diagnostics(self):
        spec = PerfWorkloadSpec(
            name="lifecycle-storm",
            minimum_exit_counts=(),
            lifecycle_minimum_counts=(("fork", 2), ("exec", 3), ("exit", 2)),
            lifecycle_stat_minimums=(
                ("lifecycle_fork_seen", 2),
                ("lifecycle_fork_parent_tracked", 2),
                ("lifecycle_fork_child_filter_installed", 2),
            ),
            lifecycle_stat_zeroes=(
                "lifecycle_fork_child_filter_failed",
            ),
        )
        lifecycle = [
            {"action": "fork"},
            {"action": "fork"},
            {"action": "exec"},
            {"action": "exec"},
            {"action": "exec"},
            {"action": "exit"},
            {"action": "exit"},
        ]
        failures = validate_perf_capture(
            make_capture(
                lifecycle_events=lifecycle,
                stats={
                    "lifecycle_fork_seen": 2,
                    "lifecycle_fork_parent_tracked": 2,
                    "lifecycle_fork_child_filter_installed": 2,
                },
            ),
            spec,
        )
        self.assertEqual(failures, [])

    def test_rejects_lifecycle_storm_diagnostic_regression(self):
        spec = PerfWorkloadSpec(
            name="lifecycle-storm",
            minimum_exit_counts=(),
            lifecycle_minimum_counts=(("fork", 2),),
            lifecycle_stat_minimums=(("lifecycle_fork_parent_tracked", 2),),
            lifecycle_stat_zeroes=("lifecycle_fork_child_filter_failed",),
        )
        failures = validate_perf_capture(
            make_capture(
                lifecycle_events=[{"action": "fork"}, {"action": "fork"}],
                stats={
                    "lifecycle_fork_parent_tracked": 1,
                    "lifecycle_fork_child_filter_failed": 1,
                },
            ),
            spec,
        )
        self.assertTrue(any("lifecycle_fork_parent_tracked" in failure for failure in failures))
        self.assertTrue(any("lifecycle_fork_child_filter_failed" in failure for failure in failures))

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

    def test_accepts_overlapping_handler_setup_phases(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        events = [{"syscall": "getpid", "event_type": "exit", "paired_enter": True}]

        failures = validate_perf_capture(make_capture(events=events), spec)

        self.assertFalse(any("BPF setup" in failure for failure in failures))

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

    def test_rejects_cleanup_phase_before_finalize(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        for event in capture.phase_events:
            if event.get("phase") == "cleanup_start":
                event["time_ns"] = 299

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("phase" in failure for failure in failures))

    def test_rejects_missing_cleanup_owner_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events = [
            event
            for event in capture.phase_events
            if event.get("phase") != "cleanup_bpf_runtime"
        ]

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("cleanup_bpf_runtime" in failure for failure in failures))

    def test_rejects_missing_bpf_cleanup_phase(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        capture.phase_events = [
            event
            for event in capture.phase_events
            if event.get("phase") != "cleanup_bpf_links"
        ]

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("cleanup_bpf_links" in failure for failure in failures))

    def test_rejects_overlapping_bpf_link_and_core_cleanup(self):
        spec = PerfWorkloadSpec(name="scalar", minimum_exit_counts=(('getpid', 1),))
        capture = make_capture(
            events=[{"syscall": "getpid", "event_type": "exit", "paired_enter": True}],
        )
        for event in capture.phase_events:
            if event.get("phase") == "cleanup_bpf_core_objects":
                event["start_time_ns"] = 306

        failures = validate_perf_capture(capture, spec)

        self.assertTrue(any("overlaps link cleanup" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
