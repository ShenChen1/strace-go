import base64
import unittest

from ebpf_epoll_suite import EPOLL_FIFO_PATH, _has_nested_epoll_path


class EpollSemanticOracleTests(unittest.TestCase):
    def test_accepts_nested_fd_path_on_successful_epoll_wait(self):
        snapshot = bytes(48) + EPOLL_FIFO_PATH.encode() + b"\x00"
        events = [{
            "syscall": "epoll_wait",
            "event_type": "exit",
            "ret": 1,
            "paired_enter": True,
            "payload_sections": [{
                "kind": "fd_path",
                "direction": "in",
                "arg_index": 0xFFFD,
                "probe_ret": 0,
                "copied_len": 64,
                "data_base64": base64.b64encode(snapshot).decode(),
            }],
        }]
        self.assertTrue(_has_nested_epoll_path(events))

    def test_rejects_unpaired_or_wrong_syscall(self):
        events = [{
            "syscall": "poll",
            "event_type": "exit",
            "ret": 1,
            "paired_enter": True,
            "payload_sections": [],
        }]
        self.assertFalse(_has_nested_epoll_path(events))
