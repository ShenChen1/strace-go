#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_aio_suite import AIO_PAYLOAD_MARKERS, check_aio_semantic


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


def event(syscall, ret, sections=()):
    return {
        "syscall": syscall,
        "event_type": "exit",
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
    timeout = bytes(16)
    wrapper = (0x6000).to_bytes(8, "little") + (8).to_bytes(8, "little")
    mask = b"\x01" + bytes(7)
    iocb = bytes(64)
    pointers = (0x7000).to_bytes(8, "little")
    first = AIO_PAYLOAD_MARKERS[0]
    return [
        event("io_setup", 0, (section("struct", "out", 1, b"\x01" * 8),)),
        event("io_submit", 1, (
            section("struct", "in", 2, pointers),
            section("struct", "in", 20, iocb),
            section("bytes", "in", 60, first),
        )),
        event("io_submit", 1, (
            section("struct", "in", 2, pointers),
            section("struct", "in", 20, iocb),
            section("bytes", "in", 60, AIO_PAYLOAD_MARKERS[1]),
        )),
        event("io_getevents", 1, (
            section("struct", "in", 4, timeout),
            section("struct", "out", 3, b"\x02" * 32),
        )),
        event("io_pgetevents", 1, (
            section("struct", "in", 4, timeout),
            section("struct", "in", 5, wrapper),
            section("bytes", "in", 5, mask),
            section("struct", "out", 3, b"\x03" * 32),
        )),
        event("io_cancel", -22, (section("struct", "in", 1, iocb),)),
        event("io_getevents", -14, (section("struct", "in", 4, timeout),)),
        event("io_pgetevents", -14, (
            section("struct", "in", 4, timeout),
            section("struct", "in", 5, wrapper),
            section("bytes", "in", 5, mask),
        )),
    ]


class AioSemanticOracleTests(unittest.TestCase):
    def test_accepts_complete_aio_capture(self):
        failures = check_aio_semantic(0, "aio-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_submit_buffer(self):
        events = copy.deepcopy(valid_events())
        submit = next(event for event in events if event["syscall"] == "io_submit")
        submit["payload_sections"] = submit["payload_sections"][:-1]
        failures = check_aio_semantic(0, "aio-fixture-ok\n", events, stats())
        self.assertIn("io_submit first buffer snapshot missing", failures)

    def test_rejects_failure_output_and_runtime_error(self):
        events = copy.deepcopy(valid_events())
        events[-1]["payload_sections"].append(section("bytes", "out", 3, b"bad"))
        runtime_stats = stats()
        runtime_stats[0]["orphan_exit"] = 1
        failures = check_aio_semantic(0, "aio-fixture-ok\n", events, runtime_stats)
        self.assertIn("AIO orphan_exit is non-zero", failures)
        self.assertIn("AIO failure fabricated OUT payload", failures)


if __name__ == "__main__":
    unittest.main()
