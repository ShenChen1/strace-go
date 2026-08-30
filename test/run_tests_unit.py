import os
import unittest

import run_tests
import upstream_suites


class ClassifyTestResultTest(unittest.TestCase):
    def test_plain_pass(self):
        result = {"test": "getpid.gen.test", "success": True, "rc": 0}

        self.assertEqual(run_tests.classify_test_result(result, {}), ("pass", ""))

    def test_plain_fail(self):
        result = {"test": "getpid.gen.test", "success": False, "rc": 1}

        self.assertEqual(run_tests.classify_test_result(result, {}), ("fail", ""))

    def test_skip_wins_over_expected_failure(self):
        result = {"test": "read-write.gen.test", "success": False, "rc": 77}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("skip", ""),
        )

    def test_expected_failure(self):
        result = {"test": "read-write.gen.test", "success": False, "rc": 1}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("xfail", "known"),
        )

    def test_unexpected_pass(self):
        result = {"test": "read-write.gen.test", "success": True, "rc": 0}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("xpass", "known"),
        )

    def test_tolerated_unexpected_pass(self):
        result = {"test": "attach-p-cmd.test", "success": True, "rc": 0}

        self.assertEqual(
            run_tests.classify_test_result(
                result,
                {"attach-p-cmd.test": "scheduler-sensitive"},
                {"attach-p-cmd.test"},
            ),
            ("xpass_allowed", "scheduler-sensitive"),
        )


class RootRequirementTest(unittest.TestCase):
    def test_root_has_no_requirement_error(self):
        self.assertEqual(run_tests.root_requirement_error(0), "")

    def test_non_root_gets_actionable_requirement_error(self):
        self.assertIn("sudo -n", run_tests.root_requirement_error(1000))


class UpstreamReferenceSuiteTest(unittest.TestCase):
    def test_qual_syscall_has_lifecycle_aware_timeout(self):
        self.assertGreaterEqual(
            run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS["qual_syscall.test"], 180
        )

    def test_strace_summary_sort_has_multi_session_timeout(self):
        self.assertGreaterEqual(
            run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS["strace-S.test"], 120
        )

    def test_detached_status_regressions_are_registered(self):
        for test in ("status-detached.test", "status-detached-threads.test"):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_signal_delivery_regressions_are_registered(self):
        for test in (
            "qual_signal.test",
            "nanosleep.gen.test",
            "clock_nanosleep.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )
        self.assertGreaterEqual(
            run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS["qual_signal.test"], 180
        )

    def test_quiet_thread_execve_regression_is_registered(self):
        test = "maybe_switch_current_tcp--quiet-thread-execve.gen.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_trace_fds_regressions_are_registered(self):
        for test in (
            "dup-trace-fds-0.gen.test",
            "dup-trace-fds-not-9.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_decode_fds_path_regressions_are_registered(self):
        for test in (
            "dev--decode-fds-all.gen.test",
            "dev--decode-fds-dev.gen.test",
            "dev--decode-fds-none.gen.test",
            "dev--decode-fds-path.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_decode_fds_socket_regressions_are_registered(self):
        for test in (
            "dev--decode-fds-socket.gen.test",
            "net--decode-fds-socket-netlink.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_non_ascii_character_escape_regression_is_registered(self):
        test = "strace--strings-in-hex-non-ascii-chars.gen.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_color_regressions_are_registered(self):
        for test in (
            "strace--color-no-tty.test",
            "strace--color-tty.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_tips_regressions_are_registered(self):
        for test in (
            "strace--tips.test",
            "strace--tips-full.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_separate_output_regressions_are_registered(self):
        for test in (
            "strace-ff.test",
            "strace--follow-forks-output-separately.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_decode_pid_comm_regression_is_registered(self):
        test = "strace--decode-pids-comm.gen.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_registered_tests_exist_in_current_upstream(self):
        valid = {
            name
            for name in os.listdir(run_tests.TESTS_DIR)
            if name.endswith(".test")
            and not name.endswith(".sh")
            and name != "strace-k.test"
        }
        registered = set(
            upstream_suites.SMOKE_TESTS
            + upstream_suites.MORE_TESTS
            + upstream_suites.UPSTREAM_REFERENCE_TESTS
        )

        self.assertEqual(sorted(registered - valid), [])

    def test_stable_more_snapshot_is_explicit_and_unique(self):
        stable = upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
        reference = upstream_suites.UPSTREAM_REFERENCE_TESTS

        self.assertEqual(len(stable), len(set(stable)))
        self.assertEqual(len(reference), len(set(reference)))
        self.assertTrue(set(stable).issubset(reference))

    def test_reference_does_not_promote_more_expected_failures(self):
        promoted = set(upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)
        expected = set(upstream_suites.MORE_EXPECTED_FAILURES)

        self.assertTrue(promoted.isdisjoint(expected))
        self.assertNotIn("strace-C.test", promoted)
        self.assertNotIn("attach-p-cmd.test", promoted)


if __name__ == "__main__":
    unittest.main()
