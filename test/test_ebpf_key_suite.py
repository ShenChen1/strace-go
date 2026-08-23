#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_key_suite import check_key_semantic


def section(kind, arg_index, data):
    return {
        "kind": kind,
        "direction": "in",
        "arg_index": arg_index,
        "user_len": len(data),
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def event(syscall, event_type, ret=0, sections=()):
    return {
        "syscall": syscall,
        "event_type": event_type,
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
        event("add_key", "enter", sections=(
            section("string", 0, b"user\x00"),
            section("string", 1, b"ebpf-key-add\x00"),
            section("bytes", 2, b"ebpf-key-payload"),
        )),
        event("add_key", "exit", -1),
        event("request_key", "enter", sections=(
            section("string", 0, b"user\x00"),
            section("string", 1, b"ebpf-key-request\x00"),
            section("string", 2, b"ebpf-key-callout\x00"),
        )),
        event("request_key", "exit", -1),
    ]


class KeySemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_key_capture(self):
        failures = check_key_semantic(0, "key-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_payload(self):
        events = copy.deepcopy(valid_events())
        events[0]["payload_sections"] = events[0]["payload_sections"][:-1]
        failures = check_key_semantic(0, "key-fixture-ok\n", events, stats())
        self.assertIn("add_key payload missing", failures)

    def test_rejects_runtime_error_and_failure_output(self):
        events = copy.deepcopy(valid_events())
        fabricated = section("bytes", 2, b"bad")
        fabricated["direction"] = "out"
        events[1]["payload_sections"] = [fabricated]
        runtime_stats = stats()
        runtime_stats[0]["orphan_exit"] = 1
        failures = check_key_semantic(0, "key-fixture-ok\n", events, runtime_stats)
        self.assertIn("key orphan_exit is non-zero", failures)
        self.assertIn("key failure fabricated OUT payload", failures)


if __name__ == "__main__":
    unittest.main()
