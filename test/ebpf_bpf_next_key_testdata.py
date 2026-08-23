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


def _attr(key_ptr, next_key_ptr):
    data = bytearray(24)
    data[0:4] = (9).to_bytes(4, "little")
    data[8:16] = key_ptr.to_bytes(8, "little")
    data[16:24] = next_key_ptr.to_bytes(8, "little")
    return bytes(data)


def next_key_events():
    null_attr = _attr(0, 0xE200)
    keyed_attr = _attr(0xE300, 0xE400)
    bad_attr = _attr(1, 0xE500)
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [4, 0xE100, len(null_attr), 0, 0, 0],
            "payload_sections": [_section("in", 1, null_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [4, 0xE100, len(null_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [_section("out", 125, b"\x00\x00\x00\x00")],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [4, 0xE300, len(keyed_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, keyed_attr),
                _section("in", 124, b"\x00\x00\x00\x00"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [4, 0xE300, len(keyed_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [_section("out", 125, b"\x01\x00\x00\x00")],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [4, 0xE500, len(bad_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, bad_attr),
                _section("in", 124, b"", user_len=4, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [4, 0xE500, len(bad_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
