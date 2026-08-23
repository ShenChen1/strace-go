#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_recvmsg_suite import check_recvmsg_semantic


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
    marker = b"rx-cmsg"
    sockaddr = bytes.fromhex("0200cfc77f0000010000000000000000")
    msghdr = bytes(56)
    iovec = bytes(16)
    cmsg = (
        (20).to_bytes(8, "little")
        + (1).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + (9).to_bytes(4, "little")
    )
    return [
        event("sendmsg", "exit", ret=7),
        event("recvmsg", "enter", sections=[
            section("struct", "in", 1, msghdr),
            section("iovec", "in", 1, iovec),
            section("cmsg", "in", 1, bytes(24)),
        ]),
        event("recvmsg", "exit", ret=7, sections=[
            section("cmsg", "out", 1, cmsg),
            section("struct", "out", 1, msghdr),
            section("bytes", "out", 120, marker),
        ], arg_text=("SCM_RIGHTS",)),
        event("sendmsg", "exit", ret=7),
        event("recvmsg", "enter", sections=[
            section("struct", "in", 1, msghdr),
            section("iovec", "in", 1, iovec),
        ]),
        event("recvmsg", "exit", ret=7, sections=[
            section("sockaddr", "out", 1, sockaddr),
            section("struct", "out", 1, msghdr),
            section("bytes", "out", 120, b"rx-name"),
        ], arg_text=("AF_INET", "127.0.0.1")),
        event("recvmsg", "exit", ret=-9),
    ]


class RecvmsgSemanticOracleTests(unittest.TestCase):
    def test_accepts_fragmented_recvmsg_capture(self):
        failures = check_recvmsg_semantic(0, "recvmsg-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_control_fragment(self):
        events = copy.deepcopy(valid_events())
        successful = next(
            event for event in events
            if event["syscall"] == "recvmsg"
            and event["event_type"] == "exit"
            and event["ret"] > 0
            and any(section["kind"] == "cmsg" for section in event["payload_sections"])
        )
        successful["payload_sections"] = [
            section for section in successful["payload_sections"]
            if section["kind"] != "cmsg"
        ]
        failures = check_recvmsg_semantic(0, "recvmsg-fixture-ok\n", events, stats())
        self.assertIn("recvmsg OUT cmsg payload missing", failures)

    def test_rejects_runtime_error_counter(self):
        runtime_stats = stats()
        runtime_stats[0]["pending_mismatch"] = 1
        failures = check_recvmsg_semantic(0, "recvmsg-fixture-ok\n", valid_events(), runtime_stats)
        self.assertIn("recvmsg pending_mismatch is non-zero", failures)


if __name__ == "__main__":
    unittest.main()
