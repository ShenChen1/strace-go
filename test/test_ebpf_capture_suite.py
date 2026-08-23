#!/usr/bin/env python3
import subprocess
import unittest

from ebpf_capture_suite import (
    CaptureRun,
    MIN_LONG_PRODUCER_ATTEMPTS,
    _count_json_events,
    _count_text_syscalls,
    _fixture_args,
    _trace_seconds,
    _validate_long_capture,
    _validate_capture,
)


def make_capture(stderr, returncode=0):
    return CaptureRun(
        name="unit",
        result=subprocess.CompletedProcess([], returncode, "", stderr),
        elapsed=0.1,
        syscall_events=_count_json_events(stderr, "syscall"),
        ready_events=[{"type": "ready"}],
        phase_events=[
            {"type": "phase", "phase": "trace_start", "time_ns": 100},
            {"type": "phase", "phase": "trace_end", "time_ns": 250},
        ],
        stats_events=[
            {
                "type": "stats",
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
                "records_read": 2,
                "producer_attempts_lower_bound": 2,
                "records_decoded": 2,
                "records_invalid": 0,
                "records_routed": 2,
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
                "service_enabled": True,
                "service_sample_rate": 1,
                "bytes_read": 192,
                "max_record_bytes": 96,
                "read_time_ns": 20,
                "decode_time_ns": 80,
                "sink_time_ns": 120,
                "min_remaining_bytes": 128,
                "service_time_ns": 200,
                "service_records": 2,
                "max_service_time_ns": 120,
                "max_remaining_bytes": 128,
            }
        ],
    )


class CaptureOracleTests(unittest.TestCase):
    def test_long_fixture_args_use_expanded_thread_workload(self):
        self.assertEqual(
            _fixture_args("/tmp/fixture", "long"),
            [
                "-f",
                "-e",
                "trace=getpid",
                "/tmp/fixture",
                "threads",
                "32",
                "100000",
            ],
        )

    def test_counts_only_requested_json_type(self):
        stderr = '{"type":"syscall"}\n{"type":"stats"}\n'

        self.assertEqual(_count_json_events(stderr, "syscall"), 1)
        self.assertEqual(_count_json_events(stderr, "lifecycle"), 0)

    def test_counts_text_syscall_lines(self):
        stderr = "getpid() = 1\nclock_gettime(1, {}) = 0\n+++ exited with 0 +++\n"

        self.assertEqual(
            _count_text_syscalls(stderr, ("getpid", "clock_gettime")), 2
        )

        self.assertEqual(
            _count_text_syscalls(
                "arch_prctl(ARCH_GET_FS, [0x1]) = 0\nget_robust_list(0, [0x2], [24]) = 0\n",
                ("arch_prctl", "get_robust_list"),
            ),
            2,
        )

    def test_validates_discard_capture_without_syscall_output(self):
        capture = make_capture('{"type":"stats"}\n')

        failures, stats = _validate_capture(capture, expect_syscalls=False)

        self.assertEqual(failures, [])
        self.assertIsNotNone(stats)
        self.assertAlmostEqual(_trace_seconds(capture), 0.00000015)

    def test_rejects_syscall_leak_from_discard_capture(self):
        capture = make_capture('{"type":"syscall"}\n')

        failures, _ = _validate_capture(capture, expect_syscalls=False)

        self.assertTrue(any("leaked" in failure for failure in failures))

    def test_requires_minimum_json_events(self):
        capture = make_capture('{"type":"syscall"}\n')

        failures, _ = _validate_capture(
            capture, expect_syscalls=True, minimum_syscall_events=2
        )

        self.assertTrue(any("want>=2" in failure for failure in failures))

    def test_rejects_runtime_drop_diagnostic_for_discard_capture(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.stats_events[0]["ringbuf_reserve_fail"] = 1

        failures, _ = _validate_capture(capture, expect_syscalls=False)

        self.assertTrue(any("ringbuf_reserve_fail=1" in failure for failure in failures))

    def test_long_capture_allows_reserve_drops_but_not_structural_errors(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.allow_reserve_fail = True
        capture.stats_events[0]["ringbuf_reserve_fail"] = 1

        failures, _ = _validate_capture(capture, expect_syscalls=False)

        self.assertEqual(failures, [])

    def test_long_capture_requires_accounting_and_valid_records(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.allow_reserve_fail = True
        stats = capture.stats_events[0]
        stats["records_read"] = MIN_LONG_PRODUCER_ATTEMPTS - 3
        stats["records_decoded"] = MIN_LONG_PRODUCER_ATTEMPTS - 3
        stats["producer_attempts_lower_bound"] = MIN_LONG_PRODUCER_ATTEMPTS
        stats["ringbuf_reserve_fail"] = 3

        failures, _ = _validate_long_capture(capture)

        self.assertEqual(failures, [])
        stats["records_invalid"] = 1
        self.assertTrue(
            any("records_invalid=1" in failure for failure in _validate_long_capture(capture)[0])
        )

    def test_rejects_incomplete_service_measurement(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.stats_events[0]["service_records"] = 3

        failures, _ = _validate_capture(capture, expect_syscalls=False)

        self.assertTrue(any("exceeds records_read" in failure for failure in failures))

    def test_requires_routed_records_for_text_capture(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.name = "text"

        failures, _ = _validate_capture(
            capture, expect_syscalls=False, expect_routed=True
        )

        self.assertEqual(failures, [])
        capture.stats_events[0]["records_routed"] = 0
        failures, _ = _validate_capture(
            capture, expect_syscalls=False, expect_routed=True
        )
        self.assertTrue(any("routed no records" in failure for failure in failures))

    def test_rejects_stage_time_above_total_service_time(self):
        capture = make_capture('{"type":"stats"}\n')
        capture.stats_events[0]["decode_time_ns"] = 201

        failures, _ = _validate_capture(capture, expect_syscalls=False)

        self.assertTrue(any("stage times exceed" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
