#!/usr/bin/env python3
import base64


def _section(kind, direction, arg_index, data):
    raw = bytes(data)
    return {
        "kind": kind,
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(raw),
        "copied_len": len(raw),
        "probe_ret": 0,
        "data_base64": base64.b64encode(raw).decode(),
    }


def task_fd_query_events():
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [20, 0x7000, 48, 0, 0, 0],
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [20, 0x7000, 48, 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                _section(
                    "bytes",
                    "out",
                    138,
                    bytes(12)
                    + (16).to_bytes(4, "little")
                    + bytes(8)
                    + (99).to_bytes(4, "little")
                    + (1).to_bytes(4, "little")
                    + bytes(32),
                ),
                _section("string", "out", 137, b"sys_enter_getpid\x00"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [20, 0x7100, 48, 0, 0, 0],
            "ret": -14,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
