import json
import subprocess
import unittest
from unittest.mock import patch

from ebpf_integrity_perf import capture


class IntegrityPerformanceTests(unittest.TestCase):
    def test_capture_separates_trace_window_from_lifecycle(self):
        events = [
            {"type": "phase", "phase": "trace_start", "time_ns": 10},
            {"type": "phase", "phase": "trace_end", "time_ns": 1000000010},
            {"type": "stats", "records_read": 20, "bytes_read": 100,
             "ringbuf_reserve_fail": 3, "ringbuf_copy_fail": 0,
             "service_records": 2, "service_time_ns": 80},
        ]
        result = subprocess.CompletedProcess([], 0, "", "\n".join(map(json.dumps, events)))
        with patch("ebpf_integrity_perf.subprocess.run", return_value=result), \
                patch("ebpf_integrity_perf.time.monotonic", side_effect=[1, 4]):
            measured = capture("tracer", "fixture", ("test", "getpid", (), 10))
        self.assertEqual(measured["trace_seconds"], 1)
        self.assertEqual(measured["end_to_end_seconds"], 3)
        self.assertEqual(measured["workload_syscalls_per_second"], 10)
        self.assertEqual(measured["service_ns_per_sample"], 40)
        self.assertEqual(measured["ringbuf_reserve_fail"], 3)

    def test_failed_load_is_not_reported_as_throughput(self):
        result = subprocess.CompletedProcess([], 1, "", "verifier rejected")
        with patch("ebpf_integrity_perf.subprocess.run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "verifier rejected"):
                capture("tracer", "fixture", ("test", "getpid", (), 10))


if __name__ == "__main__":
    unittest.main()
