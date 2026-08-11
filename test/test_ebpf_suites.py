#!/usr/bin/env python3
import base64
import subprocess
import sys
import unittest

from ebpf_event_oracles import has_dup_fd_state_sections, has_fd_state_section
from ebpf_suites import wait_for_debug_ready
from run_tests import SuiteResults


def close_child(child):
    if child.poll() is None:
        child.kill()
    child.communicate(timeout=2)


class WaitForDebugReadyTests(unittest.TestCase):
    def start_child(self, source):
        return subprocess.Popen(
            [sys.executable, "-c", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_returns_captured_prefix_after_ready(self):
        child = self.start_child(
            "import sys, time; "
            "sys.stderr.write('loading\\n{\"type\":\"ready\",\"target_pid\":42}\\n'); "
            "sys.stderr.flush(); time.sleep(0.1)"
        )
        self.addCleanup(close_child, child)
        captured = wait_for_debug_ready(child, timeout=2)
        self.assertIn("loading", captured)
        self.assertIn('"type":"ready"', captured)

    def test_reports_exit_code_and_stderr_before_ready(self):
        child = self.start_child(
            "import sys; sys.stderr.write('load failed\\n'); sys.stderr.flush(); sys.exit(7)"
        )
        self.addCleanup(close_child, child)
        with self.assertRaises(RuntimeError) as raised:
            wait_for_debug_ready(child, timeout=2)
        message = str(raised.exception)
        self.assertIn("rc=7", message)
        self.assertIn("load failed", message)


class SuiteResultsTests(unittest.TestCase):
    def test_records_expected_failure(self):
        results = SuiteResults()
        result = {"test": "bounded.test", "rc": 1, "success": False}

        outcome, reason = results.record(result, {"bounded.test": "bounded"})

        self.assertEqual((outcome, reason), ("xfail", "bounded"))
        self.assertEqual(results.counts["xfail"], 1)
        self.assertEqual(results.xfailed, [(result, "bounded")])

    def test_records_unexpected_pass(self):
        results = SuiteResults()
        result = {"test": "bounded.test", "rc": 0, "success": True}

        outcome, reason = results.record(result, {"bounded.test": "bounded"})

        self.assertEqual((outcome, reason), ("xpass", "bounded"))
        self.assertEqual(results.counts["xpass"], 1)


class EventOracleTests(unittest.TestCase):
    def test_accepts_complete_fd_state_snapshot(self):
        data = bytearray(48)
        data[0:4] = (7).to_bytes(4, "little", signed=True)
        data[4:8] = (3).to_bytes(4, "little")
        data[32:40] = (42).to_bytes(8, "little")
        events = [{
            "event_type": "exit",
            "syscall": "openat",
            "ret": 7,
            "payload_sections": [{
                "kind": "fd_state",
                "direction": "out",
                "arg_index": 0xffff,
                "user_len": 48,
                "copied_len": 48,
                "probe_ret": 0,
                "data_base64": base64.b64encode(data).decode(),
            }],
        }]

        self.assertTrue(has_fd_state_section(events))

    def test_rejects_failed_fd_state_snapshot(self):
        events = [{
            "event_type": "exit",
            "syscall": "open",
            "ret": 7,
            "payload_sections": [{
                "kind": "fd_state",
                "direction": "out",
                "arg_index": 0xffff,
                "user_len": 48,
                "copied_len": 0,
                "probe_ret": -14,
                "data_base64": "",
            }],
        }]

        self.assertFalse(has_fd_state_section(events))

    def test_accepts_complete_dup_fd_state_snapshots(self):
        events = []
        for syscall, fd in (("dup", 7), ("dup2", 8), ("dup3", 9)):
            data = bytearray(48)
            data[0:4] = fd.to_bytes(4, "little", signed=True)
            data[4:8] = (3).to_bytes(4, "little")
            data[32:40] = (42).to_bytes(8, "little")
            events.append({
                "event_type": "exit",
                "syscall": syscall,
                "ret": fd,
                "payload_sections": [{
                    "kind": "fd_state",
                    "direction": "out",
                    "arg_index": 0xffff,
                    "user_len": 48,
                    "copied_len": 48,
                    "probe_ret": 0,
                    "data_base64": base64.b64encode(data).decode(),
                }],
            })

        self.assertTrue(has_dup_fd_state_sections(events))


if __name__ == "__main__":
    unittest.main()
