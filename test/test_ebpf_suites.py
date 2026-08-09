#!/usr/bin/env python3
import subprocess
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
