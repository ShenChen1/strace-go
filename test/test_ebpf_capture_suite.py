#!/usr/bin/env python3
import subprocess
import unittest

from ebpf_capture_suite import CaptureRun, _count_json_events, _trace_seconds, _validate_capture


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
                "pending_stale": 0,
                "records_read": 2,
                "records_decoded": 2,
                "records_invalid": 0,
                "records_routed": 2,
                "max_remaining_bytes": 128,
            }
        ],
    )


class CaptureOracleTests(unittest.TestCase):
    def test_counts_only_requested_json_type(self):
        stderr = '{"type":"syscall"}\n{"type":"stats"}\n'

        self.assertEqual(_count_json_events(stderr, "syscall"), 1)
        self.assertEqual(_count_json_events(stderr, "lifecycle"), 0)

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


if __name__ == "__main__":
    unittest.main()
