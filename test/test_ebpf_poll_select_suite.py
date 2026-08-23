#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_poll_select_suite import check_poll_select_semantic


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
    poll_in = b"\x03\x00\x00\x00\x01\x00\x00\x00"
    poll_out = b"\x03\x00\x00\x00\x01\x00\x01\x00"
    timeout = bytes(16)
    sigmask = bytes(8)
    fdset = b"\x08"
    timeval = bytes(16)
    wrapper = (0x6000).to_bytes(8, "little") + (8).to_bytes(8, "little")
    sigmask = b"\x01" + bytes(7)
    return [
        event("poll", "enter", sections=(section("struct", "in", 0, poll_in),)),
        event("poll", "exit", 1, (section("struct", "out", 0, poll_out),), ("POLLIN",)),
        event("ppoll", "enter", sections=(
            section("struct", "in", 0, poll_in),
            section("struct", "in", 2, timeout),
            section("struct", "in", 3, sigmask),
        )),
        event("ppoll", "exit", 1, (
            section("struct", "out", 0, poll_out),
            section("struct", "out", 2, timeout),
        ), ("POLLIN",)),
        event("select", "enter", sections=(
            section("bytes", "in", 1, fdset),
            section("bytes", "in", 2, fdset),
            section("bytes", "in", 3, fdset),
            section("struct", "in", 4, timeval),
        )),
        event("select", "exit", 1, (
            section("bytes", "out", 1, fdset),
            section("bytes", "out", 2, fdset),
            section("struct", "out", 4, timeval),
        )),
        event("pselect6", "enter", sections=(
            section("bytes", "in", 1, fdset),
            section("struct", "in", 4, timeout),
            section("struct", "in", 5, wrapper),
            section("struct", "in", 6, sigmask),
        ), arg_text=("{sigmask=[HUP], sigsetsize=8}",)),
        event("pselect6", "exit", 1, (
            section("bytes", "out", 1, fdset),
            section("struct", "out", 4, timeout),
        )),
        event("poll", "exit", -14),
        event("ppoll", "exit", -14),
        event("select", "exit", -14),
        event("pselect6", "exit", -14),
    ]


class PollSelectSemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_poll_select_capture(self):
        failures = check_poll_select_semantic(
            0, "poll-select-fixture-ok\n", valid_events(), stats()
        )
        self.assertEqual(failures, [])

    def test_rejects_missing_select_output_snapshot(self):
        events = copy.deepcopy(valid_events())
        select_exit = next(
            event for event in events
            if event["syscall"] == "select" and event["event_type"] == "exit"
            and event["ret"] == 1
        )
        select_exit["payload_sections"] = []
        failures = check_poll_select_semantic(
            0, "poll-select-fixture-ok\n", events, stats()
        )
        self.assertIn("select OUT fdset missing", failures)

    def test_rejects_failure_output_and_runtime_error(self):
        events = copy.deepcopy(valid_events())
        events[-1]["payload_sections"] = [section("bytes", "out", 1, b"\x08")]
        runtime_stats = stats()
        runtime_stats[0]["orphan_exit"] = 1
        failures = check_poll_select_semantic(
            0, "poll-select-fixture-ok\n", events, runtime_stats
        )
        self.assertIn("poll-select orphan_exit is non-zero", failures)
        self.assertIn("poll-select failure fabricated OUT payload", failures)


if __name__ == "__main__":
    unittest.main()
