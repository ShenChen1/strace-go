#!/usr/bin/env python3
import base64


def _section(kind, direction, arg_index, data, user_len=None, probe_ret=0):
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


def delete_batch_events():
    attr = bytearray(56)
    attr[16:24] = (0xD100).to_bytes(8, "little")
    attr[32:36] = (1).to_bytes(4, "little")
    attr[36:40] = (7).to_bytes(4, "little")
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [27, 0xD000, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("bytes", "in", 1, attr),
                _section("bytes", "in", 121, b"\x00\x00\x00\x00", user_len=4),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [27, 0xD000, len(attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [27, 0xD200, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("bytes", "in", 1, attr),
                _section("bytes", "in", 121, b"", user_len=8, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [27, 0xD200, len(attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [
                _section("bytes", "in", 1, attr),
                _section("bytes", "in", 123, b"", user_len=4, probe_ret=-14),
            ],
        },
    ]


def delete_elem_events():
    attr = bytearray(24)
    attr[0:4] = (7).to_bytes(4, "little")
    attr[8:16] = (0xC100).to_bytes(8, "little")
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [3, 0xC000, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("bytes", "in", 1, attr),
                _section("bytes", "in", 123, b"\x07\x00\x00\x00"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [3, 0xC000, len(attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [3, 0xC200, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("bytes", "in", 1, attr),
                _section("bytes", "in", 123, b"", user_len=4, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [3, 0xC200, len(attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
