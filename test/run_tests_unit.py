import os
import unittest
from unittest import mock

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


class UpstreamEnvironmentTest(unittest.TestCase):
    def test_x86_environment_defines_empty_mips_abi(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            run_tests.setup_env()

            self.assertEqual(os.environ["MIPS_ABI"], "")

    def test_upstream_configuration_disables_optional_ptrace_features(self):
        args = run_tests.UPSTREAM_CONFIGURE_ARGS

        self.assertIn("--enable-mpers=no", args)
        self.assertIn("--enable-stacktrace=no", args)
        self.assertIn("--without-libiberty", args)
        self.assertIn("--without-libselinux", args)


class UpstreamReferenceSuiteTest(unittest.TestCase):
    def test_qual_syscall_has_lifecycle_aware_timeout(self):
        self.assertGreaterEqual(
            run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS["qual_syscall.test"], 180
        )

    def test_syscall_selector_syntax_is_candidate(self):
        test = "filtering_syscall-syntax.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertGreaterEqual(run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS[test], 180)

    def test_descriptor_selector_syntax_is_registered(self):
        test = "filtering_fd-syntax.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_unknown_syscall_regressions_are_registered(self):
        for test in ("nsyscalls.test", "nsyscalls-nd.test", "nsyscalls-d.test"):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_syscall_personality_regressions_are_candidates(self):
        for test in self.syscall_personality_regressions():
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertGreaterEqual(run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS[test], 180)

    def test_syscall_selector_regressions_are_stable(self):
        regressions = (
            "filtering_syscall-syntax.test",
            *self.syscall_personality_regressions(),
        )
        for test in regressions:
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    @staticmethod
    def syscall_personality_regressions():
        return (
            "trace_personality_64.gen.test",
            "trace_personality_32.gen.test",
            "trace_personality_x32.gen.test",
            "trace_personality_number_64.gen.test",
            "trace_personality_regex_64.gen.test",
            "trace_personality_statfs_64.gen.test",
            "trace_personality_all_32.gen.test",
            "trace_personality_all_x32.gen.test",
        )

    def test_trace_group_regressions_have_qualifier_timeout(self):
        for test in (
            "trace_clock.gen.test",
            "trace_fstat.gen.test",
            "trace_fstatfs.gen.test",
            "trace_stat_like.gen.test",
            "trace_statfs.gen.test",
            "trace_statfs_like.gen.test",
        ):
            self.assertGreaterEqual(run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS[test], 180)

        for test in ("trace_fstat.gen.test", "trace_stat_like.gen.test"):
            self.assertGreaterEqual(run_tests.UPSTREAM_TEST_TIMEOUT_SECONDS[test], 600)

    def test_trace_group_regressions_are_candidates(self):
        for test in self.trace_group_regressions():
            self.assertIn(test, upstream_suites.MORE_TESTS)

    def test_trace_group_regressions_are_stable(self):
        for test in self.trace_group_regressions():
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    @staticmethod
    def trace_group_regressions():
        return (
            "xettimeofday.gen.test",
            "trace_clock.gen.test",
            "trace_fstat.gen.test",
            "trace_fstatfs.gen.test",
            "trace_stat_like.gen.test",
            "trace_statfs.gen.test",
            "trace_statfs_like.gen.test",
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

    def test_status_qualifier_regressions_are_registered(self):
        for test in (
            "status-successful-status.gen.test",
            "status-failed-status.gen.test",
            "status-unfinished.gen.test",
        ):
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

    def test_instruction_pointer_regression_is_registered(self):
        test = "pc.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_namespace_new_regressions_are_registered(self):
        for test in (
            "clone3-report-ns-id.gen.test",
            "setns-report-ns-id.gen.test",
            "unshare-report-ns-id.gen.test",
        ):
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

    def test_pidns_cache_regression_is_registered(self):
        test = "pidns-cache.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_quiet_thread_execve_regression_is_registered(self):
        test = "maybe_switch_current_tcp--quiet-thread-execve.gen.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

    def test_trace_fds_regressions_are_registered(self):
        for test in (
            "dup-trace-fds-0.gen.test",
            "dup-trace-fds-0-9.gen.test",
            "dup-trace-fds-not-9.gen.test",
            "ppoll-e-trace-fds-23.gen.test",
            "ppoll-e-trace-fds-23-42.gen.test",
            "ppoll-e-trace-fds-not-9-42-P.gen.test",
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

    def test_decode_fds_netlink_modes_are_registered(self):
        for test in (
            "net--decode-fds-all-netlink.gen.test",
            "net--decode-fds-dev-netlink.gen.test",
            "net--decode-fds-none-netlink.gen.test",
            "net--decode-fds-path-netlink.gen.test",
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

    def test_version_regression_is_registered(self):
        test = "strace-V.test"
        self.assertIn(test, upstream_suites.MORE_TESTS)
        self.assertIn(test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)

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

    def test_output_alias_regressions_are_registered(self):
        tests = (
            "strace--strings-in-hex.gen.test",
            "strace--strings-in-hex-none.gen.test",
            "strace--strings-in-hex-all.gen.test",
            "strace--strings-in-hex-non-ascii.gen.test",
            "strace-no-x.gen.test",
            "strace--timestamps-time-ms.gen.test",
            "strace--timestamps-time-ns.gen.test",
            "strace--timestamps-time-s.gen.test",
            "strace--timestamps-time-us.gen.test",
            "strace--timestamps-time.gen.test",
            "strace--timestamps-unix-ms.gen.test",
            "strace--timestamps-unix-ns.gen.test",
            "strace--timestamps-unix-s.gen.test",
            "strace--timestamps-unix-us.gen.test",
            "strace--timestamps.gen.test",
            "strace-Y-0123456789.gen.test",
            "strace-p-Y-p.test",
        )
        for test in tests:
            self.assertIn(test, upstream_suites.MORE_TESTS)
            self.assertIn(
                test, upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
            )

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
        self.assertIn("strace-C.test", promoted)
        self.assertNotIn("strace-C.test", expected)
        self.assertNotIn("attach-p-cmd.test", promoted)


if __name__ == "__main__":
    unittest.main()
