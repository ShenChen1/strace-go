#!/usr/bin/env python3
import unittest
from types import SimpleNamespace

from ebpf_no_ptrace_suite import check_no_ptrace_fixture, parse_tracer_pid


class NoPtraceOracleTests(unittest.TestCase):
    def test_parse_tracer_pid_reads_status_field(self):
        self.assertEqual(
            parse_tracer_pid("Name:\tfixture\nTracerPid:\t0\nState:\tR\n"),
            0,
        )
        self.assertEqual(
            parse_tracer_pid("Name:\tfixture\nTracerPid:\t42\n"),
            42,
        )

    def test_parse_tracer_pid_rejects_missing_or_malformed_field(self):
        self.assertIsNone(parse_tracer_pid("Name:\tfixture\n"))
        self.assertIsNone(parse_tracer_pid("TracerPid:\tbad\n"))

    def test_oracle_accepts_clean_fixture(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="TracerPid: 0\nno-ptrace-fixture-ok\n",
            stderr="",
        )
        self.assertEqual(check_no_ptrace_fixture(result), [])

    def test_oracle_reports_fixture_failure(self):
        result = SimpleNamespace(returncode=71, stdout="", stderr="TracerPid=42\n")
        self.assertEqual(
            check_no_ptrace_fixture(result),
            [
                "no-ptrace fixture rc=71",
                "no-ptrace fixture marker missing",
                "no-ptrace fixture TracerPid observation missing",
            ],
        )


if __name__ == "__main__":
    unittest.main()
