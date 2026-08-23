#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_xattr_suite import check_xattr_semantic


def section(kind, direction, arg_index, data, user_len=None):
    length = len(data) if user_len is None else user_len
    return {
        "kind": kind,
        "direction": direction,
        "arg_index": arg_index,
        "user_len": length,
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def event(syscall, event_type, ret=0, sections=(), arg_text=()):
    return {
        "syscall": syscall,
        "event_type": event_type,
        "ret": ret,
        "failed": ret < 0,
        "paired_enter": True,
        "payload_sections": list(sections),
        "arg_text": list(arg_text),
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
    result.update(available=True, service_enabled=True, stage_enabled=True)
    result["service_sample_rate"] = 64
    result["stage_sample_rate"] = 64
    return [result]


def valid_events():
    path = b"/tmp/strace-go-ebpf-xattr-abc123\x00"
    name = b"user.fixture\x00"
    value = b"xattr-value"
    listed = b"user.fixture\x00"
    return [
        event("setxattr", "enter", sections=(
            section("string", "in", 0, path),
            section("string", "in", 1, name),
            section("bytes", "in", 2, value),
        )),
        event("setxattr", "exit"),
        event("getxattr", "enter", sections=(
            section("string", "in", 0, path),
            section("string", "in", 1, name),
        )),
        event("getxattr", "exit", len(value), (
            section("bytes", "out", 2, value),
        )),
        event("listxattr", "enter", sections=(
            section("string", "in", 0, path),
        )),
        event("listxattr", "exit", len(listed), (
            section("bytes", "out", 1, listed),
        )),
        event("removexattr", "enter", sections=(
            section("string", "in", 0, path),
            section("string", "in", 1, name),
        )),
        event("removexattr", "exit"),
        event("getxattr", "enter", sections=(
            section("string", "in", 0, path),
            section("string", "in", 1, name),
        )),
        event("getxattr", "exit", -61),
    ]


class XattrSemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_xattr_capture(self):
        failures = check_xattr_semantic(0, "xattr-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_get_output_snapshot(self):
        events = copy.deepcopy(valid_events())
        get_exit = next(
            event for event in events
            if event["syscall"] == "getxattr" and event["event_type"] == "exit"
            and event["ret"] > 0
        )
        get_exit["payload_sections"] = []
        failures = check_xattr_semantic(0, "xattr-fixture-ok\n", events, stats())
        self.assertIn("getxattr OUT value missing", failures)

    def test_rejects_failure_output_and_runtime_error(self):
        events = copy.deepcopy(valid_events())
        failed_exit = events[-1]
        failed_exit["payload_sections"] = [section("bytes", "out", 2, b"bad")]
        runtime_stats = stats()
        runtime_stats[0]["pending_mismatch"] = 1
        failures = check_xattr_semantic(0, "xattr-fixture-ok\n", events, runtime_stats)
        self.assertIn("xattr pending_mismatch is non-zero", failures)
        self.assertIn("xattr failure fabricated OUT payload", failures)


if __name__ == "__main__":
    unittest.main()
