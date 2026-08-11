#!/usr/bin/env python3
import base64
import subprocess
import sys
import unittest

from ebpf_event_oracles import (
    has_dup_fd_state_sections,
    has_fd_array_fd_state_sections,
    has_fcntl_fd_state_for_command,
    has_fd_state_for_syscall,
    has_fd_state_section,
)
from ebpf_cloexec_suite import has_stale_cloexec_read
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
    def test_detects_stale_cloexec_read(self):
        events = [{"syscall": "read", "event_type": "exit", "ret": -9}]
        self.assertTrue(has_stale_cloexec_read(events))
        self.assertFalse(has_stale_cloexec_read([{"syscall": "read", "ret": 0}]))

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
        self.assertTrue(has_fd_state_for_syscall(events, "openat"))
        self.assertFalse(has_fd_state_for_syscall(events, "eventfd2"))

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

    def test_accepts_two_complete_fd_array_snapshots(self):
        events = []
        for syscall, first_fd in (("pipe", 7), ("pipe2", 9), ("socketpair", 11)):
            sections = []
            for fd, inode in ((first_fd, 42), (first_fd + 1, 43)):
                data = bytearray(48)
                data[0:4] = fd.to_bytes(4, "little", signed=True)
                data[4:8] = (3).to_bytes(4, "little")
                data[32:40] = inode.to_bytes(8, "little")
                sections.append({
                    "kind": "fd_state",
                    "direction": "out",
                    "arg_index": 0xffff,
                    "user_len": 48,
                    "copied_len": 48,
                    "probe_ret": 0,
                    "data_base64": base64.b64encode(data).decode(),
                })
            events.append({
                "event_type": "exit",
                "syscall": syscall,
                "ret": 0,
                "payload_sections": sections,
            })

        self.assertTrue(has_fd_array_fd_state_sections(events))

    def test_accepts_only_dup_commands_as_fcntl_fd_state(self):
        events = []
        for command, fd in ((0, 7), (1030, 8)):
            data = bytearray(48)
            data[0:4] = fd.to_bytes(4, "little", signed=True)
            data[4:8] = (3).to_bytes(4, "little")
            data[32:40] = (42).to_bytes(8, "little")
            events.append({
                "event_type": "exit",
                "syscall": "fcntl",
                "args": [5, command, 20, 0, 0, 0],
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
        events.append({
            "event_type": "exit",
            "syscall": "fcntl",
            "args": [5, 3, 0, 0, 0, 0],
            "ret": 32768,
            "payload_sections": [],
        })

        self.assertTrue(has_fcntl_fd_state_for_command(events, 0))
        self.assertTrue(has_fcntl_fd_state_for_command(events, 1030))
        self.assertFalse(has_fcntl_fd_state_for_command(events, 3))


if __name__ == "__main__":
    unittest.main()
