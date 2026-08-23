#!/usr/bin/env python3
import base64


def section(kind, direction, arg_index, data, user_len=None, probe_ret=0):
    raw = bytes(data)
    return {
        "kind": kind,
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(raw) if user_len is None else user_len,
        "copied_len": len(raw),
        "probe_ret": probe_ret,
        "data_base64": base64.b64encode(raw).decode(),
    }


def clean_stats(**overrides):
    stats = {
        "available": True,
        "service_enabled": False,
        "stage_enabled": False,
    }
    for key in (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "payload_truncated_events",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
        "lifecycle_map_update_fail",
        "lifecycle_fork_seen",
        "lifecycle_fork_parent_tracked",
        "lifecycle_fork_parent_untracked",
        "lifecycle_fork_child_filter_installed",
        "lifecycle_fork_child_filter_failed",
        "lifecycle_exec_seen",
        "lifecycle_exec_untracked",
        "lifecycle_exit_seen",
        "lifecycle_exit_untracked",
        "pending_stale",
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
        stats[key] = 0
    stats.update(overrides)
    return stats


def percpu_batch_attr(elem_flags):
    data = bytearray(56)
    data[8:16] = (0xA000).to_bytes(8, "little")
    data[16:24] = (0xA100).to_bytes(8, "little")
    data[24:32] = (0xA200).to_bytes(8, "little")
    data[32:36] = (1).to_bytes(4, "little")
    data[36:40] = (9).to_bytes(4, "little")
    data[40:48] = elem_flags.to_bytes(8, "little")
    return bytes(data)


def percpu_lookup_attr(elem_flags):
    data = bytearray(32)
    data[0:4] = (9).to_bytes(4, "little")
    data[8:16] = (0xB000).to_bytes(8, "little")
    data[16:24] = (0xB100).to_bytes(8, "little")
    data[24:32] = elem_flags.to_bytes(8, "little")
    return bytes(data)


def percpu_events():
    events = []
    updates = (
        (0, b"percpu-no-flags", 48),
        (8, b"percpu-cpu", 16),
        (16, b"percpu-all-cpus", 16),
    )
    for index, (flags, marker, user_len) in enumerate(updates):
        attr = percpu_batch_attr(flags)
        events.extend(
            [
                {
                    "syscall": "bpf",
                    "event_type": "enter",
                    "args": [26, 0xA000 + index * 0x100, len(attr), 0, 0, 0],
                    "payload_sections": [
                        section("bytes", "in", 1, attr),
                        section("bytes", "in", 121, b"percpu-key"),
                        section("bytes", "in", 122, marker, user_len=user_len),
                    ],
                },
                {
                    "syscall": "bpf",
                    "event_type": "exit",
                    "args": [26, 0xA000 + index * 0x100, len(attr), 0, 0, 0],
                    "ret": 0,
                    "paired_enter": True,
                    "payload_sections": [],
                },
            ]
        )
    batch_attr = percpu_batch_attr(0)
    events.extend(
        [
            {
                "syscall": "bpf",
                "event_type": "enter",
                "args": [24, 0xA400, len(batch_attr), 0, 0, 0],
                "payload_sections": [section("bytes", "in", 1, batch_attr)],
            },
            {
                "syscall": "bpf",
                "event_type": "exit",
                "args": [24, 0xA400, len(batch_attr), 0, 0, 0],
                "ret": 0,
                "paired_enter": True,
                "payload_sections": [
                    section("bytes", "out", 120, b"next", user_len=4),
                    section("bytes", "out", 118, b"percpu-key", user_len=4),
                    section("bytes", "out", 119, b"percpu-no-flags", user_len=48),
                ],
            },
            {
                "syscall": "bpf",
                "event_type": "enter",
                "args": [1, 0xA500, 32, 0, 0, 0],
                "payload_sections": [
                    section("bytes", "in", 1, percpu_lookup_attr(8)),
                ],
            },
            {
                "syscall": "bpf",
                "event_type": "exit",
                "args": [1, 0xA500, 32, 0, 0, 0],
                "ret": 0,
                "paired_enter": True,
                "payload_sections": [
                    section("bytes", "out", 117, b"percpu-cpu", user_len=16),
                ],
            },
        ]
    )
    return events


def attach_detach_events():
    events = []
    for command in (8, 9):
        attr = bytes(16)
        events.extend(
            [
                {
                    "syscall": "bpf",
                    "event_type": "enter",
                    "args": [command, 0xC000 + command, len(attr), 0, 0, 0],
                    "payload_sections": [section("bytes", "in", 1, attr)],
                },
                {
                    "syscall": "bpf",
                    "event_type": "exit",
                    "args": [command, 0xC000 + command, len(attr), 0, 0, 0],
                    "ret": 0,
                    "paired_enter": True,
                    "payload_sections": [],
                },
            ]
        )
    return events
