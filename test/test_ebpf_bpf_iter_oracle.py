import unittest

from ebpf_bpf_iter_oracle import check_bpf_iter


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


def _event(event_type, command, ret=None):
    event = {
        "syscall": "bpf",
        "event_type": event_type,
        "args": [command, 0x1000, 168, 0, 0, 0],
        "payload_sections": [],
    }
    if event_type == "enter":
        event["payload_sections"] = [
            {
                "kind": "bytes",
                "direction": "in",
                "arg_index": 1,
                "probe_ret": 0,
                "copied_len": 168,
            }
        ]
    else:
        event["ret"] = ret
        event["paired_enter"] = True
    return event


class BpfIterOracleTest(unittest.TestCase):
    def test_accepts_success_and_failure_contracts(self):
        events = []
        for command in (5, 28):
            events.extend([_event("enter", command), _event("exit", command, 3)])
        events.extend(
            [
                _event("enter", 33),
                _event("exit", 33, 5),
                _event("enter", 33),
                _event("exit", 33, -9),
            ]
        )
        self.assertEqual(
            check_bpf_iter(0, "bpf-iter-fixture-ok bytes=0", events, [_stats()]), []
        )

    def test_rejects_missing_iterator_success(self):
        events = []
        for command in (5, 28):
            events.extend([_event("enter", command), _event("exit", command, 3)])
        events.extend(
            [
                _event("enter", 33),
                _event("exit", 33, -9),
                _event("enter", 33),
                _event("exit", 33, -9),
            ]
        )
        failures = check_bpf_iter(0, "bpf-iter-fixture-ok", events, [_stats()])
        self.assertIn("BPF_ITER_CREATE success missing", failures)


if __name__ == "__main__":
    unittest.main()
