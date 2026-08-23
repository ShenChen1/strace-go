import unittest
from contextlib import ExitStack
from unittest import mock

import ebpf_extended_semantic


RUNNERS = (
    "run_no_ptrace_semantic",
    "run_epoll_semantic",
    "run_cloexec_semantic",
    "run_ioctl_semantic",
    "run_key_semantic",
    "run_keyctl_semantic",
    "run_signalfd_semantic",
    "run_network_semantic",
    "run_poll_select_semantic",
    "run_recvmsg_semantic",
    "run_sockopt_semantic",
    "run_xattr_semantic",
    "run_aio_semantic",
    "run_bpf_semantic",
    "run_bpf_iter_semantic",
    "run_bpf_rare_semantic",
    "run_bpf_stream_semantic",
    "run_bpf_struct_ops_semantic",
)


class ExtendedSemanticSuiteTests(unittest.TestCase):
    def test_runs_specialized_suites_in_declared_order(self):
        calls = []

        def fake_runner(*args, name):
            calls.append((name, args))
            return []

        with ExitStack() as stack:
            for name in RUNNERS:
                stack.enter_context(
                    mock.patch.object(
                        ebpf_extended_semantic,
                        name,
                        side_effect=lambda *args, _name=name: fake_runner(
                            *args, name=_name
                        ),
                    )
                )
            self.assertEqual(
                ebpf_extended_semantic.run_extended_semantic_suites(
                    "wrapper", "root"
                ),
                [],
            )

        self.assertEqual([name for name, _ in calls], list(RUNNERS))
        self.assertEqual(calls[0][1], ("wrapper", "root"))
        self.assertEqual(calls[-1][1], ("wrapper", "root"))


if __name__ == "__main__":
    unittest.main()
