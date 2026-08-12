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
    )


class PerfOracleTests(unittest.TestCase):
    def test_parses_go_benchmark_allocation_metrics(self):
        output = (
            "BenchmarkTraceEventDecodeState-8  1000  123.4 ns/op  96 B/op  2 allocs/op\n"
            "BenchmarkJSONEventWriter-8  500  456.7 ns/op  128 B/op  3 allocs/op\n"
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


if __name__ == "__main__":
    unittest.main()
