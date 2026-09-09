#!/usr/bin/env python3
import subprocess
import unittest
from unittest import mock

import ebpf_signalfd_suite


class SignalFDSuiteTests(unittest.TestCase):
    @mock.patch.object(ebpf_signalfd_suite, "build_fixture", return_value="/tmp/signalfd")
    @mock.patch.object(ebpf_signalfd_suite.subprocess, "run")
    def test_uses_signalfd_detail_mode_for_mask_return_text(
        self, run, build_fixture
    ):
        run.return_value = subprocess.CompletedProcess([], 1, "", "")

        ebpf_signalfd_suite.run_signalfd_semantic("wrapper", "/project")

        build_fixture.assert_called_once_with("/project")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["wrapper", "--event-format=json", "--decode-fds=signalfd"])
        self.assertIn("trace=signalfd,signalfd4,close,exit,exit_group", command)


if __name__ == "__main__":
    unittest.main()
