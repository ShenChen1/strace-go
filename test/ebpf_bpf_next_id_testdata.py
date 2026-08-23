#!/usr/bin/env python3
import base64


def _section(direction, data, user_ptr, arg_index):
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": arg_index,
        "user_ptr": user_ptr,
        "user_len": len(data),
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def next_id_events():
    attr = b"\x07\x00\x00\x00\x07\x00\x00\x00"
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [12, 0x5000, 8, 0, 0, 0],
            "payload_sections": [_section("in", attr, 0x5000, 1)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [12, 0x5000, 8, 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [_section("out", b"*\x00\x00\x00", 0x5004, 140)],
        },
    ]
