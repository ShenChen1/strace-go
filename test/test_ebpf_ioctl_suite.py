#!/usr/bin/env python3
import base64
import copy
import unittest

from ebpf_ioctl_suite import check_ioctl_semantic


def payload(direction, data):
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": 2,
        "user_len": len(data),
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def event(event_type, ret, sections=(), paired=True, arg_text=()):
    return {
        "syscall": "ioctl",
        "event_type": event_type,
        "ret": ret,
        "failed": ret < 0,
        "paired_enter": paired,
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
    in_data = (0xFFFFFFFF).to_bytes(4, "little")
    out_data = (17).to_bytes(4, "little")
    return [
        event("enter", 0, [payload("in", in_data)], arg_text=("FIONREAD",)),
        event("exit", 0, [payload("out", out_data)], arg_text=("FIONREAD", "[17]")),
        event("exit", -9),
    ]


class IoctlSemanticOracleTests(unittest.TestCase):
    def test_accepts_fionread_input_output_and_failure(self):
        failures = check_ioctl_semantic(0, "ioctl-fixture-ok\n", valid_events(), stats())
        self.assertEqual(failures, [])

    def test_rejects_missing_output_snapshot(self):
        events = copy.deepcopy(valid_events())
        events[1]["payload_sections"] = []
        failures = check_ioctl_semantic(0, "ioctl-fixture-ok\n", events, stats())
        self.assertIn("ioctl OUT payload missing", failures)

    def test_rejects_nonzero_runtime_counter(self):
        runtime_stats = stats()
        runtime_stats[0]["ringbuf_copy_fail"] = 1
        failures = check_ioctl_semantic(0, "ioctl-fixture-ok\n", valid_events(), runtime_stats)
        self.assertIn("ioctl ringbuf_copy_fail is non-zero", failures)


if __name__ == "__main__":
    unittest.main()
