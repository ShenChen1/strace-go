#!/usr/bin/env python3
import copy
import unittest

from ebpf_bpf_stream_oracle import check_bpf_stream, has_stream_read_output
from ebpf_bpf_stream_testdata import stream_read_events


class BpfStreamOracleTests(unittest.TestCase):
    def test_accepts_exit_output_and_readable_failed_buffer(self):
        self.assertTrue(has_stream_read_output(stream_read_events()))

    def test_accepts_complete_stream_contract(self):
        self.assertEqual(
            check_bpf_stream(
                0,
                "bpf-stream-fixture-ok",
                stream_read_events(),
                [_stats()],
            ),
            [],
        )

    def test_rejects_enter_stream_snapshot(self):
        events = copy.deepcopy(stream_read_events())
        events[0]["payload_sections"].append(
            {
                "kind": "bytes",
                "direction": "in",
                "arg_index": 111,
                "user_len": 11,
                "copied_len": 11,
                "probe_ret": 0,
                "data_base64": "c3RhbGU=",
            }
        )
        self.assertFalse(has_stream_read_output(events))

    def test_rejects_unpaired_stream_exit(self):
        events = stream_read_events()
        events[-1]["paired_enter"] = False
        failures = check_bpf_stream(
            0, "bpf-stream-fixture-ok", events, [_stats()]
        )
        self.assertIn("BPF stream success/failure contract missing", failures)


def _stats():
    values = {
        "available": True,
        "service_enabled": False,
        "stage_enabled": False,
    }
    zero_keys = (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
        "lifecycle_map_update_fail",
        "pending_stale",
    )
    values.update({key: 0 for key in zero_keys})
    lifecycle_keys = (
        "lifecycle_fork_seen",
        "lifecycle_fork_parent_tracked",
        "lifecycle_fork_parent_untracked",
        "lifecycle_fork_child_filter_installed",
        "lifecycle_fork_child_filter_failed",
        "lifecycle_exec_seen",
        "lifecycle_exec_untracked",
        "lifecycle_exit_seen",
        "lifecycle_exit_untracked",
    )
    values.update({key: 0 for key in lifecycle_keys})
    numeric_keys = (
        "payload_truncated_events",
        "service_sample_rate",
        "bytes_read",
        "max_record_bytes",
        "read_time_ns",
        "decode_time_ns",
        "sink_time_ns",
        "min_remaining_bytes",
        "service_time_ns",
        "service_records",
        "max_service_time_ns",
        "records_read",
        "records_decoded",
        "records_invalid",
        "records_routed",
        "max_remaining_bytes",
        "producer_attempts_lower_bound",
        "syscall_output_bytes",
        "syscall_output_writes",
        "syscall_output_write_errors",
        "syscall_write_time_ns",
        "syscall_write_time_samples",
        "stage_sample_rate",
        "state_time_ns",
        "state_records",
        "max_state_time_ns",
        "dispatch_time_ns",
        "dispatch_records",
        "max_dispatch_time_ns",
    )
    values.update({key: 0 for key in numeric_keys})
    return values


if __name__ == "__main__":
    unittest.main()
