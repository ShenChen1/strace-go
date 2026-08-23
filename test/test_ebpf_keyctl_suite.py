#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_keyctl_suite import check_keyctl_semantic


def section(kind, direction, arg_index, data):
    return {
        "kind": kind,
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(data),
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def event(operation, event_type, args, ret=0, sections=()):
    return {
        "syscall": "keyctl",
        "event_type": event_type,
        "args": [operation, *args],
        "ret": ret,
        "failed": ret < 0,
        "paired_enter": True,
        "payload_sections": list(sections),
    }


def stats():
    keys = (
        "ringbuf_reserve_fail", "ringbuf_copy_fail", "payload_truncated_events",
        "pending_update_fail", "orphan_exit", "pending_mismatch",
        "lifecycle_map_update_fail", "lifecycle_fork_seen",
        "lifecycle_fork_parent_tracked", "lifecycle_fork_parent_untracked",
        "lifecycle_fork_child_filter_installed", "lifecycle_fork_child_filter_failed",
        "lifecycle_exec_seen", "lifecycle_exec_untracked", "lifecycle_exit_seen",
        "lifecycle_exit_untracked", "pending_stale", "service_sample_rate",
        "bytes_read", "max_record_bytes", "read_time_ns", "decode_time_ns",
        "sink_time_ns", "min_remaining_bytes", "service_time_ns", "service_records",
        "max_service_time_ns", "records_read", "records_decoded", "records_invalid",
        "records_routed", "max_remaining_bytes", "producer_attempts_lower_bound",
        "syscall_output_bytes", "syscall_output_writes", "syscall_output_write_errors",
        "syscall_write_time_ns", "syscall_write_time_samples", "stage_sample_rate",
        "state_time_ns", "state_records", "max_state_time_ns", "dispatch_time_ns",
        "dispatch_records", "max_dispatch_time_ns",
    )
    result = {key: 0 for key in keys}
    result.update(available=True, service_enabled=False, stage_enabled=False)
    return [result]


def valid_events():
    return [
        event(1, "enter", [0x1000, 0, 0, 0, 0], sections=(
            section("string", "in", 1, b"ebpf-keyctl-session\x00"),
        )),
        event(1, "exit", [0x1000, 0, 0, 0, 0], 1),
        event(2, "enter", [1, 0x2000, 18, 0, 0], sections=(
            section("bytes", "in", 2, b"ebpf-keyctl-update"),
        )),
        event(2, "exit", [1, 0x2000, 18, 0, 0], -1),
        event(6, "enter", [1, 0x3000, 0x4000, 256, 0]),
        event(6, "exit", [1, 0x3000, 0x4000, 256, 0], 36, sections=(
            section("bytes", "out", 2, b"user;1000;1000;3f010000;ebpf-keyctl-key\x00"),
        )),
        event(10, "enter", [0, 0x4000, 0x5000, 0, 0], sections=(
            section("string", "in", 2, b"user\x00"),
            section("string", "in", 3, b"ebpf-keyctl-key\x00"),
        )),
        event(10, "exit", [0, 0x4000, 0x5000, 0, 0], -1),
        event(11, "enter", [1, 0x6000, 0x7000, 256, 0]),
        event(11, "exit", [1, 0x6000, 0x7000, 256, 0], 18, sections=(
            section("bytes", "out", 2, b"ebpf-keyctl-update"),
        )),
        event(31, "enter", [0x7000, 64, 0, 0, 0]),
        event(31, "exit", [0x7000, 64, 0, 0, 0], 2, sections=(
            section("bytes", "out", 1, b"\xff\x07"),
        )),
        event(19, "enter", [0x8000, 30, 0x2000, 0x3000, 0]),
        event(19, "exit", [0x8000, 30, 0x2000, 0x3000, 0], -1),
    ]


class KeyctlSemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_keyctl_capture(self):
        failures = check_keyctl_semantic(0, "keyctl-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_keyctl_payload(self):
        events = copy.deepcopy(valid_events())
        events[5]["payload_sections"] = []
        failures = check_keyctl_semantic(0, "keyctl-fixture-ok\n", events, stats())
        self.assertIn("keyctl operation 6 arg 2 payload missing", failures)

    def test_rejects_runtime_error_and_fabricated_output(self):
        events = copy.deepcopy(valid_events())
        events[3]["payload_sections"] = [
            section("bytes", "out", 2, b"bad")
        ]
        runtime_stats = stats()
        runtime_stats[0]["orphan_exit"] = 1
        failures = check_keyctl_semantic(0, "keyctl-fixture-ok\n", events, runtime_stats)
        self.assertIn("keyctl orphan_exit is non-zero", failures)
        self.assertIn("keyctl failure fabricated OUT payload", failures)

    def test_rejects_unsupported_reject_payload(self):
        events = copy.deepcopy(valid_events())
        events[-2]["payload_sections"] = [
            section("bytes", "in", 2, b"not-a-payload")
        ]
        failures = check_keyctl_semantic(0, "keyctl-fixture-ok\n", events, stats())
        self.assertIn("keyctl reject captured unsupported payload", failures)


if __name__ == "__main__":
    unittest.main()
