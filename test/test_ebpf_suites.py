#!/usr/bin/env python3
import subprocess
import sys
import unittest
from types import SimpleNamespace

from ebpf_lifecycle_checks import check_lifecycle, check_thread
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


def _non_leader_stats():
    return {
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
        "service_enabled": False,
        "service_sample_rate": 0,
        "bytes_read": 0,
        "max_record_bytes": 0,
        "read_time_ns": 0,
        "decode_time_ns": 0,
        "sink_time_ns": 0,
        "min_remaining_bytes": 0,
        "service_time_ns": 0,
        "service_records": 0,
        "max_service_time_ns": 0,
        "records_read": 0,
        "producer_attempts_lower_bound": 0,
        "records_decoded": 0,
        "records_invalid": 0,
        "records_routed": 0,
        "max_remaining_bytes": 0,
        "syscall_output_bytes": 0,
        "syscall_output_writes": 0,
        "syscall_output_write_errors": 0,
        "syscall_write_time_ns": 0,
        "syscall_write_time_samples": 0,
        "stage_enabled": False,
        "stage_sample_rate": 0,
        "state_time_ns": 0,
        "state_records": 0,
        "max_state_time_ns": 0,
        "dispatch_time_ns": 0,
        "dispatch_records": 0,
        "max_dispatch_time_ns": 0,
    }


def _non_leader_context():
    events = [
        {"syscall": "getpid", "pid": 10, "tid": 11, "event_type": "exit", "paired_enter": True},
        {"syscall": "execve", "pid": 10, "tid": 11, "event_type": "exit", "paired_enter": True},
    ]
    lifecycle = [
        {"action": "fork", "task_tid": 11, "arg1": 11},
        {"action": "exec", "pid": 10, "task_tid": 10, "task_tgid": 10, "arg0": 11, "task_executable": "/bin/true"},
        {"action": "exit", "pid": 10, "task_tid": 10, "task_tgid": 10, "alive": False, "task_executable": "/bin/true"},
    ]
    return SimpleNamespace(
        thread=SimpleNamespace(
            result=SimpleNamespace(returncode=0, stdout="thread-fixture-ok\n"),
            events=events,
            lifecycle_events=lifecycle,
            stats_events=[_non_leader_stats()],
        ),
        thread_text=SimpleNamespace(
            returncode=0,
            stdout="thread-fixture-ok\n",
            stderr=(
                "read( <unfinished ...>\n"
                "<... read resumed>) = 1\n"
                "superseded by execve\n"
                "<... execve resumed>) = 0\n"
            ),
        ),
    )


class LifecycleCheckTests(unittest.TestCase):
    def test_requires_executable_state_on_exit(self):
        events = [
            {
                "action": "fork",
                "pid": 1,
                "task_tid": 2,
                "arg1": 2,
                "parent_tid": 1,
                "arg0": 1,
                "alive": True,
            },
            {
                "action": "exec",
                "pid": 2,
                "task_tid": 2,
                "execed": True,
                "alive": True,
                "filename": "/bin/true",
                "task_executable": "/bin/true",
            },
            {"action": "exit", "pid": 2, "task_tid": 2, "alive": False},
        ]
        context = SimpleNamespace(
            main=SimpleNamespace(
                events=[{"pid": 1}, {"pid": 2}],
                lifecycle_events=events,
            )
        )

        failures = []
        check_lifecycle(context, failures)
        self.assertEqual(failures, ["exit/free lifecycle lost task executable state"])

        events[-1]["task_executable"] = "/bin/true"
        failures = []
        check_lifecycle(context, failures)
        self.assertEqual(failures, [])

    def test_accepts_non_leader_exec_identity_migration(self):
        context = _non_leader_context()
        failures = []
        check_thread(context, failures)
        self.assertEqual(failures, [])

        context.thread.lifecycle_events[-1].pop("task_executable")
        failures = []
        check_thread(context, failures)
        self.assertEqual(
            failures,
            ["non-leader exec exit/free lost migrated executable state"],
        )


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

    def test_records_tolerated_unexpected_pass(self):
        results = SuiteResults()
        result = {"test": "attach-p-cmd.test", "rc": 0, "success": True}

        outcome, reason = results.record(
            result,
            {"attach-p-cmd.test": "scheduler-sensitive"},
            {"attach-p-cmd.test"},
        )

        self.assertEqual((outcome, reason), ("xpass_allowed", "scheduler-sensitive"))
        self.assertEqual(results.counts["xpass_allowed"], 1)
        self.assertEqual(results.xpassed_allowed, [(result, "scheduler-sensitive")])


if __name__ == "__main__":
    unittest.main()
