#!/usr/bin/env python3
import base64


def _section(kind, arg_index, data, user_ptr):
    return {
        "kind": kind,
        "direction": "in",
        "arg_index": arg_index,
        "user_ptr": user_ptr,
        "user_len": len(data),
        "copied_len": len(data),
        "probe_ret": 0,
        "data_base64": base64.b64encode(data).decode(),
    }


def uprobe_events():
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [28, 0x1000, 60],
            "payload_sections": [
                _section("bytes", 1, b"attr", 0x1000),
                _section("string", 133, b"/tmp/bpf-fixture\x00", 0x2000),
                _section("bytes", 134, (0x111).to_bytes(8, "little"), 0x3000),
                _section("bytes", 136, (0x222).to_bytes(8, "little"), 0x4000),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [28, 0x1000, 60],
            "ret": -22,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
