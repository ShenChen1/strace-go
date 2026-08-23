#!/usr/bin/env python3
import base64


def _section(direction, arg_index, data, user_len=None, probe_ret=0):
    raw = bytes(data)
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(raw) if user_len is None else user_len,
        "copied_len": len(raw),
        "probe_ret": probe_ret,
        "data_base64": base64.b64encode(raw).decode(),
    }


def update_elem_events():
    attr = bytearray(32)
    attr[0:4] = (7).to_bytes(4, "little")
    attr[8:16] = (0xF100).to_bytes(8, "little")
    attr[16:24] = (0xF200).to_bytes(8, "little")
    large_value = b"large-map-value" + bytes(64 - len(b"large-map-value"))
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [2, 0xF000, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr),
                _section("in", 126, b"\x00\x00\x00\x00"),
                _section("in", 127, b"map-value", user_len=16),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [2, 0xF000, len(attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [2, 0xF210, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr),
                _section("in", 126, b"\x01\x00\x00\x00"),
                _section("in", 127, large_value, user_len=64),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [2, 0xF210, len(attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [2, 0xF300, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr),
                _section("in", 126, b"", user_len=4, probe_ret=-14),
                _section("in", 127, b"", user_len=16, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [2, 0xF300, len(attr), 0, 0, 0],
            "ret": -14,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
