import base64
import struct


def _section(direction, arg_index, data, user_ptr, user_len=None, probe_ret=0):
    raw = bytes(data)
    return {
        "kind": "bytes",
        "direction": direction,
        "arg_index": arg_index,
        "user_ptr": user_ptr,
        "user_len": len(raw) if user_len is None else user_len,
        "copied_len": len(raw),
        "probe_ret": probe_ret,
        "data_base64": base64.b64encode(raw).decode(),
    }


def prog_load_fd_array_events():
    attr = bytearray(168)
    attr[120:128] = (0x6000).to_bytes(8, "little")
    attr[148:152] = (2).to_bytes(4, "little")
    bad_attr = bytearray(attr)
    bad_attr[120:128] = (1).to_bytes(8, "little")
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3000, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr, 0x3000),
                _section("in", 141, (17).to_bytes(4, "little") + (23).to_bytes(4, "little"), 0x6000),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3000, len(attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3100, len(bad_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, bad_attr, 0x3100),
                _section("in", 141, b"", 1, user_len=4, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3100, len(bad_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def prog_load_func_info_events():
    attr = bytearray(168)
    attr[76:80] = (8).to_bytes(4, "little")
    attr[80:88] = (0x7000).to_bytes(8, "little")
    attr[88:92] = (2).to_bytes(4, "little")
    bad_attr = bytearray(attr)
    bad_attr[80:88] = (1).to_bytes(8, "little")
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3200, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr, 0x3200),
                _section(
                    "in",
                    142,
                    (0).to_bytes(4, "little")
                    + (0x1234).to_bytes(4, "little")
                    + (8).to_bytes(4, "little")
                    + (0x5678).to_bytes(4, "little"),
                    0x7000,
                ),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3200, len(attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3300, len(bad_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, bad_attr, 0x3300),
                _section("in", 142, b"", 1, user_len=8, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3300, len(bad_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def prog_load_line_info_events():
    attr = bytearray(168)
    attr[92:96] = (16).to_bytes(4, "little")
    attr[96:104] = (0x8000).to_bytes(8, "little")
    attr[104:108] = (2).to_bytes(4, "little")
    bad_attr = bytearray(attr)
    bad_attr[96:104] = (1).to_bytes(8, "little")
    records = struct.pack(
        "<8I", 0, 4, 8, 0x10001, 16, 20, 24, 0x20002
    )
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3400, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr, 0x3400),
                _section("in", 143, records, 0x8000),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3400, len(attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3500, len(bad_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, bad_attr, 0x3500),
                _section("in", 143, b"", 1, user_len=16, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3500, len(bad_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def prog_load_core_relos_events():
    attr = bytearray(168)
    attr[116:120] = (2).to_bytes(4, "little")
    attr[128:136] = (0x9000).to_bytes(8, "little")
    attr[136:140] = (16).to_bytes(4, "little")
    bad_attr = bytearray(attr)
    bad_attr[128:136] = (1).to_bytes(8, "little")
    records = struct.pack(
        "<8I", 0, 0x1234, 4, 1, 16, 0x5678, 8, 2
    )
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3600, len(attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, attr, 0x3600),
                _section("in", 144, records, 0x9000),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3600, len(attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x3700, len(bad_attr), 0, 0, 0],
            "payload_sections": [
                _section("in", 1, bad_attr, 0x3700),
                _section("in", 144, b"", 1, user_len=32, probe_ret=-14),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x3700, len(bad_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]
