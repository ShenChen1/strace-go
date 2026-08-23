#!/usr/bin/env python3
import base64


def _section(arg_index, data, direction="in", probe_ret=0):
    raw = bytes(data)
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": arg_index,
        "user_len": len(raw),
        "copied_len": len(raw),
        "probe_ret": probe_ret,
        "data_base64": base64.b64encode(raw).decode(),
    }


def lookup_events():
    events = []
    for command, pointer, marker in (
        (1, 0x5100, b"lookup-key"),
        (21, 0x5200, b"delete-key"),
    ):
        attr = bytearray(32)
        attr[8:16] = pointer.to_bytes(8, "little")
        attr[16:24] = (pointer + 0x100).to_bytes(8, "little")
        events.extend(
            [
                {
                    "syscall": "bpf",
                    "event_type": "enter",
                    "args": [command, pointer + 0x1000, len(attr), 0, 0, 0],
                    "payload_sections": [
                        _section(1, attr),
                        _section(139, marker),
                    ],
                },
                {
                    "syscall": "bpf",
                    "event_type": "exit",
                    "args": [command, pointer + 0x1000, len(attr), 0, 0, 0],
                    "ret": 0,
                    "paired_enter": True,
                    "payload_sections": [
                        _section(117, b"map-value", direction="out"),
                    ],
                },
            ]
        )
    events.extend(
        [
            {
                "syscall": "bpf",
                "event_type": "enter",
                "args": [1, 0x9000, 64, 0, 0, 0],
                "payload_sections": [_section(139, b"bad-key", probe_ret=-14)],
            },
            {
                "syscall": "bpf",
                "event_type": "exit",
                "args": [1, 0x9000, 64, 0, 0, 0],
                "ret": -14,
                "paired_enter": True,
                "payload_sections": [],
            },
        ]
    )
    return events
