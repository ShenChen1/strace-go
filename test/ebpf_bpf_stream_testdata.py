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


def stream_read_events():
    attr = bytearray(20)
    attr[0:8] = (0x9000).to_bytes(8, "little")
    attr[8:12] = (11).to_bytes(4, "little")
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [37, 0x8000, len(attr), 0, 0, 0],
            "payload_sections": [_section("in", 1, attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [37, 0x8000, len(attr), 0, 0, 0],
            "ret": 11,
            "paired_enter": True,
            "payload_sections": [
                _section("in", 1, attr),
                _section("out", 111, b"stream-data", user_len=11),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [37, 0x8100, len(attr), 0, 0, 0],
            "payload_sections": [_section("in", 1, attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [37, 0x8100, len(attr), 0, 0, 0],
            "ret": -9,
            "paired_enter": True,
            "payload_sections": [
                _section("in", 1, attr),
                _section("out", 111, b"stream-data", user_len=11),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [37, 0x8200, len(attr), 0, 0, 0],
            "payload_sections": [_section("in", 1, attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [37, 0x8200, len(attr), 0, 0, 0],
            "ret": -2,
            "paired_enter": True,
            "payload_sections": [
                _section("in", 1, attr),
                _section("out", 111, b"stream-data", user_len=11),
            ],
        },
    ]
