import io
import os
import subprocess
import unittest
from unittest import mock

import run_tests


class ConfiguredUpstreamInventoryTest(unittest.TestCase):
    def test_configured_tests_are_parsed_strictly_and_sorted(self):
        output = "write.gen.test\nread.gen.test\nwrite.gen.test\n"

        self.assertEqual(
            run_tests.parse_configured_upstream_tests(output),
            ["read.gen.test", "write.gen.test"],
        )

    def test_configured_tests_reject_unexpected_make_output(self):
        with self.assertRaisesRegex(
            run_tests.UpstreamSetupError, "unexpected configured test entry"
        ):
            run_tests.parse_configured_upstream_tests(
                "read.gen.test\nmake: entering directory\n"
            )

    def test_all_suite_uses_configured_make_inventory(self):
        configured = ["getpid.gen.test", "read.gen.test"]
        with mock.patch.object(
            run_tests, "configured_upstream_tests", return_value=configured
        ) as configured_tests, mock.patch.object(
            os, "listdir", side_effect=AssertionError("directory scan is forbidden")
        ):
            tests = run_tests.get_tests("all")

        self.assertEqual(tests, configured)
        configured_tests.assert_called_once_with()

    def test_configured_inventory_is_read_through_make(self):
        with mock.patch.object(
            run_tests,
            "run_upstream_command",
            return_value="write.gen.test\nread.gen.test\n",
        ) as run_command:
            tests = run_tests.configured_upstream_tests()

        self.assertEqual(tests, ["read.gen.test", "write.gen.test"])
        command, cwd, stage = run_command.call_args.args
        self.assertEqual(cwd, run_tests.TESTS_DIR)
        self.assertEqual(stage, "configured upstream test inventory")
        self.assertIn("Makefile", command)
        self.assertEqual(
            run_command.call_args.kwargs["input_text"],
            run_tests.CONFIGURED_TESTS_MAKE_RULE,
        )

    def test_filter_and_limit_apply_to_configured_inventory(self):
        args = mock.Mock(suite="all", filter="read.gen.test", limit=1)
        with mock.patch.object(
            run_tests,
            "configured_upstream_tests",
            return_value=["getpid.gen.test", "read.gen.test"],
        ):
            tests = run_tests.selected_tests(args)

        self.assertEqual(tests, ["read.gen.test"])


class UpstreamPrerequisiteBuildTest(unittest.TestCase):
    def test_build_upstream_builds_prerequisites_once(self):
        with mock.patch.object(os.path, "isfile", return_value=True), mock.patch.object(
            run_tests.multiprocessing, "cpu_count", return_value=8
        ), mock.patch.object(
            run_tests, "run_upstream_command"
        ) as run_command, mock.patch("builtins.print"):
            run_tests.build_upstream()

        self.assertEqual(run_command.call_count, 2)
        self.assertEqual(
            run_command.call_args_list[0],
            mock.call(["make", "-j8"], run_tests.UPSTREAM_DIR, "upstream build"),
        )
        self.assertEqual(
            run_command.call_args_list[1],
            mock.call(
                [
                    "make",
                    "--no-print-directory",
                    "-C",
                    "tests",
                    "check-prerequisites-local",
                ],
                run_tests.UPSTREAM_DIR,
                "upstream test prerequisite build",
            ),
        )

    def test_upstream_command_reports_build_failure(self):
        failed = subprocess.CompletedProcess(
            ["make", "-j2"], 2, stdout="compile stdout", stderr="compile stderr"
        )
        with mock.patch.object(subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                run_tests.UpstreamSetupError, "upstream build failed with exit code 2"
            ) as raised:
                run_tests.run_upstream_command(
                    ["make", "-j2"], run_tests.UPSTREAM_DIR, "upstream build"
                )

        self.assertIn("compile stdout", str(raised.exception))
        self.assertIn("compile stderr", str(raised.exception))

    def test_upstream_suite_returns_setup_error(self):
        args = mock.Mock(skip_build=False)
        with mock.patch.object(
            run_tests,
            "build_upstream",
            side_effect=run_tests.UpstreamSetupError("helper build failed"),
        ), mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            rc = run_tests.run_upstream_suite(args)

        self.assertEqual(rc, 2)
        self.assertIn("helper build failed", stderr.getvalue())

    def test_skip_build_does_not_build_prerequisites(self):
        args = mock.Mock(
            skip_build=True,
            suite="small",
            parallel=1,
            filter="",
            limit=0,
        )
        with mock.patch.object(run_tests, "build_upstream") as build, mock.patch.object(
            run_tests, "selected_tests", return_value=[]
        ), mock.patch("builtins.print"):
            rc = run_tests.run_upstream_suite(args)

        self.assertEqual(rc, 0)
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
