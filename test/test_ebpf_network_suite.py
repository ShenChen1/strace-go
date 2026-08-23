#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_network_suite import NETWORK_PAYLOAD_MARKER, check_network_semantic


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


def event(syscall, event_type, ret=0, sections=(), paired=True, arg_text=None):
    return {
        "syscall": syscall,
        "event_type": event_type,
        "ret": ret,
        "failed": ret < 0,
        "paired_enter": paired,
        "payload_sections": list(sections),
        "arg_text": list(arg_text or []),
    }


def valid_stats():
    keys = {
        "ringbuf_reserve_fail": 0,
        "ringbuf_copy_fail": 0,
        "payload_truncated_events": 0,
        "pending_update_fail": 0,
        "orphan_exit": 0,
        "pending_mismatch": 0,
        "lifecycle_map_update_fail": 0,
        "lifecycle_fork_seen": 0,
        "lifecycle_fork_parent_tracked": 0,
        "lifecycle_fork_parent_untracked": 0,
        "lifecycle_fork_child_filter_installed": 0,
        "lifecycle_fork_child_filter_failed": 0,
        "lifecycle_exec_seen": 0,
        "lifecycle_exec_untracked": 0,
        "lifecycle_exit_seen": 0,
        "lifecycle_exit_untracked": 0,
        "pending_stale": 0,
        "service_sample_rate": 64,
        "bytes_read": 0,
        "max_record_bytes": 0,
        "read_time_ns": 0,
        "decode_time_ns": 0,
        "sink_time_ns": 0,
        "min_remaining_bytes": 0,
        "service_time_ns": 0,
        "service_records": 0,
        "max_service_time_ns": 0,
        "records_read": 0,
        "records_decoded": 0,
        "records_invalid": 0,
        "records_routed": 0,
        "max_remaining_bytes": 0,
        "producer_attempts_lower_bound": 0,
        "syscall_output_bytes": 0,
        "syscall_output_writes": 0,
        "syscall_output_write_errors": 0,
        "syscall_write_time_ns": 0,
        "syscall_write_time_samples": 0,
        "stage_sample_rate": 64,
        "state_time_ns": 0,
        "state_records": 0,
        "max_state_time_ns": 0,
        "dispatch_time_ns": 0,
        "dispatch_records": 0,
        "max_dispatch_time_ns": 0,
        "available": True,
        "service_enabled": True,
        "stage_enabled": True,
    }
    return [keys]


def valid_events():
    sockaddr = bytes.fromhex("02001f907f0000010000000000000000")
    socklen = (16).to_bytes(4, "little")
    marker = NETWORK_PAYLOAD_MARKER
    text = ['{sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}']
    events = [
        event("bind", "enter", sections=[section("struct", "in", 1, sockaddr)]),
        event("bind", "exit"),
        event("connect", "enter", sections=[section("struct", "in", 1, sockaddr)], arg_text=text),
        event("connect", "exit", arg_text=text),
        event("accept", "enter", sections=[section("bytes", "in", 2, socklen)]),
        event("accept", "exit", sections=[section("struct", "out", 1, sockaddr), section("bytes", "out", 2, socklen)], arg_text=text),
        event("accept4", "enter", sections=[section("bytes", "in", 2, socklen)]),
        event("accept4", "exit", sections=[section("struct", "out", 1, sockaddr), section("bytes", "out", 2, socklen)], arg_text=text),
        event("getsockname", "enter", sections=[section("bytes", "in", 2, socklen)]),
        event("getsockname", "exit", sections=[section("struct", "out", 1, sockaddr), section("bytes", "out", 2, socklen)], arg_text=text),
        event("getpeername", "enter", sections=[section("bytes", "in", 2, socklen)]),
        event("getpeername", "exit", sections=[section("struct", "out", 1, sockaddr), section("bytes", "out", 2, socklen)], arg_text=text),
        event("sendto", "enter", sections=[section("bytes", "in", 1, marker), section("struct", "in", 4, sockaddr)], arg_text=text),
        event("sendto", "exit"),
        event("recvfrom", "enter", sections=[section("bytes", "in", 5, socklen)]),
        event("recvfrom", "exit", sections=[section("bytes", "out", 1, marker), section("struct", "out", 4, sockaddr), section("bytes", "out", 5, socklen)], arg_text=text),
        event("connect", "exit", -9),
        event("sendto", "exit", -9),
        event("recvfrom", "exit", -9),
    ]
    return events


class NetworkSemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_network_capture(self):
        failures = check_network_semantic(0, "network-fixture-ok\n", valid_events(), valid_stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_recvfrom_snapshot(self):
        events = copy.deepcopy(valid_events())
        recv_exit = next(
            event for event in events
            if event["syscall"] == "recvfrom" and event["event_type"] == "exit" and event["ret"] == 0
        )
        recv_exit["payload_sections"] = []
        failures = check_network_semantic(0, "network-fixture-ok\n", events, valid_stats())
        self.assertTrue(any("recvfrom OUT buffer" in failure for failure in failures))

    def test_rejects_runtime_error_counter(self):
        stats = valid_stats()
        stats[0]["pending_mismatch"] = 1
        failures = check_network_semantic(0, "network-fixture-ok\n", valid_events(), stats)
        self.assertIn("network pending_mismatch is non-zero", failures)


if __name__ == "__main__":
    unittest.main()
