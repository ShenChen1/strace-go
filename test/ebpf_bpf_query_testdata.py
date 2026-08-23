#!/usr/bin/env python3
import base64


def _section(arg_index, data, direction="out"):
    raw = bytes(data)
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(raw),
        "copied_len": len(raw),
        "probe_ret": 0,
        "data_base64": base64.b64encode(raw).decode(),
    }


def _u32(value):
    return int(value).to_bytes(4, "little")


def query_events():
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [16, 0x8000, 64, 0, 0, 0],
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [16, 0x8000, 64, 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                _section(132, _u32(2)),
                _section(128, _u32(11) + _u32(22)),
                _section(129, _u32(1) + _u32(3)),
                _section(130, _u32(33) + _u32(44)),
                _section(131, _u32(2) + _u32(4)),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [16, 0x8100, 64, 0, 0, 0],
            "ret": -14,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
