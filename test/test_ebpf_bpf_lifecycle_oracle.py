import base64
import unittest

from ebpf_bpf_lifecycle_oracle import check_bpf_lifecycle


def _stats():
    values = {
        "available": True,
        "service_enabled": False,
        "stage_enabled": False,
    }
    keys = (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
        "lifecycle_map_update_fail",
        "pending_stale",
    )
    values.update({key: 0 for key in keys})
    for key in (
        "lifecycle_fork_seen",
        "lifecycle_fork_parent_tracked",
        "lifecycle_fork_parent_untracked",
        "lifecycle_fork_child_filter_installed",
        "lifecycle_fork_child_filter_failed",
        "lifecycle_exec_seen",
        "lifecycle_exec_untracked",
        "lifecycle_exit_seen",
        "lifecycle_exit_untracked",
        "payload_truncated_events",
    ):
        values[key] = 0
    for key in (
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
    ):
        values[key] = 0
    return values


def _event(event_type, command, ret=None, paired=False, string_arg=0):
    event = {
        "syscall": "bpf",
        "event_type": event_type,
        "args": [command, 0x1000, 64, 0, 0, 0],
        "payload_sections": [],
    }
    if event_type == "enter":
        event["payload_sections"] = [
            {
                "kind": "bytes",
                "direction": "in",
                "arg_index": 1,
                "probe_ret": 0,
                "copied_len": 16,
            }
        ]
        if string_arg:
            marker = (
                b"sys_enter"
                if string_arg == 105
                else b"strace-go-bpf-no-object"
            )
            event["payload_sections"].append(
                {
                    "kind": "string",
                    "direction": "in",
                    "arg_index": string_arg,
                    "probe_ret": 0,
                    "copied_len": len(marker),
                    "data_base64": base64.b64encode(marker).decode(),
                }
            )
    else:
        event["ret"] = ret
        event["paired_enter"] = paired
    return event


class BpfLifecycleOracleTest(unittest.TestCase):
    def test_accepts_success_and_failure_paths(self):
        events = []
        for command in (13, 14, 22, 32, 35, 28, 29, 30, 31, 34, 11, 23):
            events.extend([_event("enter", command), _event("exit", command, 0, True)])
        for command in (13, 14, 2, 29, 30, 34):
            events.extend([_event("enter", command), _event("exit", command, -1, True)])
        events.extend(
            [
                _event("enter", 19),
                _event("exit", 19, 0, True),
                _event("enter", 19),
                _event("exit", 19, -1, True),
                _event("enter", 17, string_arg=105),
                _event("exit", 17, 0, True),
                _event("enter", 17, string_arg=105),
                _event("exit", 17, -1, True),
            ]
        )
        for command in (6, 7):
            events.extend(
                [_event("enter", command, string_arg=104), _event("exit", command, -1, True)]
            )
        self.assertEqual(
            check_bpf_lifecycle(0, "bpf-lifecycle-fixture-ok", events, [_stats()]), []
        )

    def test_rejects_missing_map_freeze(self):
        events = []
        for command in (13, 14, 32):
            events.extend([_event("enter", command), _event("exit", command, 0, True)])
        for command in (13, 14, 2):
            events.extend([_event("enter", command), _event("exit", command, -1, True)])
        failures = check_bpf_lifecycle(
            0, "bpf-lifecycle-fixture-ok", events, [_stats()]
        )
        self.assertIn("BPF_MAP_FREEZE attr snapshot missing", failures)


if __name__ == "__main__":
    unittest.main()
