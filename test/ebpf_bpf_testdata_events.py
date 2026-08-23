#!/usr/bin/env python3

from ebpf_bpf_delete_testdata import delete_batch_events, delete_elem_events
from ebpf_bpf_lookup_testdata import lookup_events
from ebpf_bpf_next_id_testdata import next_id_events
from ebpf_bpf_next_key_testdata import next_key_events
from ebpf_bpf_prog_load_testdata import (
    prog_load_core_relos_events,
    prog_load_fd_array_events,
    prog_load_func_info_events,
    prog_load_line_info_events,
)
from ebpf_bpf_query_testdata import query_events
from ebpf_bpf_task_fd_query_testdata import task_fd_query_events
from ebpf_bpf_update_testdata import update_elem_events
from ebpf_bpf_uprobe_testdata import uprobe_events
from ebpf_bpf_testdata_core import attach_detach_events, percpu_events, section


def _event_attributes():
    map_attr = b"strace_go_map\x00" + bytes(24)
    map_lookup_attr = bytearray(32)
    map_lookup_attr[0:4] = (7).to_bytes(4, "little")
    map_lookup_attr[8:16] = (0x5000).to_bytes(8, "little")
    map_lookup_attr[16:24] = (0x5100).to_bytes(8, "little")
    batch_attr = bytearray(56)
    batch_attr[8:16] = (0x6000).to_bytes(8, "little")
    batch_attr[16:24] = (0x6100).to_bytes(8, "little")
    batch_attr[24:32] = (0x6200).to_bytes(8, "little")
    batch_attr[32:36] = (2).to_bytes(4, "little")
    batch_attr[36:40] = (7).to_bytes(4, "little")
    prog_attr = bytes(8) + bytes(8) + bytes(8)
    info_attr = bytearray(16)
    info_attr[4:8] = (64).to_bytes(4, "little")
    info_attr[8:16] = (0x3000).to_bytes(8, "little")
    btf_attr = bytearray(32)
    btf_attr[8:16] = (0x4000).to_bytes(8, "little")
    btf_attr[16:20] = (9).to_bytes(4, "little")
    btf_attr[20:24] = (256).to_bytes(4, "little")
    btf_attr[24:28] = (1).to_bytes(4, "little")
    test_attr = bytearray(80)
    test_attr[8:12] = (4).to_bytes(4, "little")
    test_attr[12:16] = (8).to_bytes(4, "little")
    test_attr[16:24] = (0x7000).to_bytes(8, "little")
    test_attr[24:32] = (0x7100).to_bytes(8, "little")
    test_attr[40:44] = (4).to_bytes(4, "little")
    test_attr[44:48] = (8).to_bytes(4, "little")
    test_attr[48:56] = (0x7200).to_bytes(8, "little")
    test_attr[56:64] = (0x7300).to_bytes(8, "little")
    invalid_test_attr = bytearray(test_attr)
    invalid_test_attr[0:4] = (0xFFFFFFFF).to_bytes(4, "little")
    return (
        map_attr,
        map_lookup_attr,
        batch_attr,
        prog_attr,
        info_attr,
        btf_attr,
        test_attr,
        invalid_test_attr,
    )


def _map_events(map_attr, map_lookup_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [0, 0x1000, len(map_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, map_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [0, 0x1000, len(map_attr), 0, 0, 0],
            "ret": 7,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [1, 0x1200, len(map_lookup_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, map_lookup_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [1, 0x1200, len(map_lookup_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 117, b"map-value", user_len=16)
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [1, 0x1300, len(map_lookup_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, map_lookup_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [1, 0x1300, len(map_lookup_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [21, 0x1400, len(map_lookup_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, map_lookup_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [21, 0x1400, len(map_lookup_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 117, b"map-value", user_len=16)
            ],
        },
    ]


def _batch_value_events(batch_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [24, 0x1500, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [24, 0x1500, len(batch_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 120, b"next", user_len=4),
                section("bytes", "out", 118, b"key-one!", user_len=8),
                section("bytes", "out", 119, b"value-one", user_len=16),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [24, 0x1600, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [24, 0x1600, len(batch_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [25, 0x1700, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [25, 0x1700, len(batch_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 120, b"next", user_len=4),
                section("bytes", "out", 118, b"key-one!", user_len=8),
                section("bytes", "out", 119, b"value-one", user_len=16),
            ],
        },
    ]


def _batch_update_events(batch_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [26, 0x1780, len(batch_attr), 0, 0, 0],
            "payload_sections": [
                section("bytes", "in", 1, batch_attr),
                section("bytes", "in", 121, b"update-key!"),
                section("bytes", "in", 122, b"update-value!"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [26, 0x1780, len(batch_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [26, 0x1790, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [26, 0x1790, len(batch_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def _batch_cursor_events(batch_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [24, 0x1720, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [24, 0x1720, len(batch_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 120, b"next", user_len=4),
                section("bytes", "out", 118, b"A", user_len=1),
                section("bytes", "out", 119, b"cursor-value", user_len=16),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [24, 0x1750, len(batch_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, batch_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [24, 0x1750, len(batch_attr), 0, 0, 0],
            "ret": -2,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 120, b"next", user_len=4),
                section("bytes", "out", 118, b"key-one!", user_len=8),
                section("bytes", "out", 119, b"value-one", user_len=16),
            ],
        },
    ]


def _object_info_events(map_attr, info_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [15, 0x1800, len(info_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, info_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [15, 0x1800, len(info_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 113, b"strace_go_map\x00", user_len=64)
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [15, 0x1900, len(info_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, info_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [15, 0x1900, len(info_attr), 0, 0, 0],
            "ret": -14,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [0, 0x1100, len(map_attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def _btf_events(btf_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [18, 0x2800, len(btf_attr), 0, 0, 0],
            "payload_sections": [
                section("bytes", "in", 1, btf_attr),
                section("bytes", "in", 106, b"bPf\x00daTum"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [18, 0x2800, len(btf_attr), 0, 0, 0],
            "ret": -22,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 114, b"btf-verifier-log", user_len=256)
            ],
        },
    ]


def _test_run_events(test_attr, invalid_test_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [10, 0x2900, len(test_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, test_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [10, 0x2900, len(test_attr), 0, 0, 0],
            "ret": 0,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 115, b"data-out", user_len=8),
                section("bytes", "out", 116, b"ctx-out!", user_len=8),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [10, 0x2A00, len(invalid_test_attr), 0, 0, 0],
            "payload_sections": [section("bytes", "in", 1, invalid_test_attr)],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [10, 0x2A00, len(invalid_test_attr), 0, 0, 0],
            "ret": -9,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [],
        },
    ]


def _prog_load_events(prog_attr):
    return [
        {
            "syscall": "bpf",
            "event_type": "enter",
            "args": [5, 0x2000, len(prog_attr), 0, 0, 0],
            "payload_sections": [
                section("bytes", "in", 1, prog_attr),
                section("bytes", "in", 112, b"\xff\x00\x00\x00\x00\x00\x00\x00"),
                section("string", "in", 101, b"GPL\x00"),
                section("bytes", "in", 102, b"bpf-verifier-log"),
            ],
        },
        {
            "syscall": "bpf",
            "event_type": "exit",
            "args": [5, 0x2000, len(prog_attr), 0, 0, 0],
            "ret": -1,
            "failed": True,
            "paired_enter": True,
            "payload_sections": [
                section("bytes", "out", 102, b"verifier-log", user_len=256)
            ],
        },
    ]


def valid_events():
    (
        map_attr,
        map_lookup_attr,
        batch_attr,
        prog_attr,
        info_attr,
        btf_attr,
        test_attr,
        invalid_test_attr,
    ) = _event_attributes()
    return (
        _map_events(map_attr, map_lookup_attr)
        + _batch_value_events(batch_attr)
        + _batch_update_events(batch_attr)
        + _batch_cursor_events(batch_attr)
        + _object_info_events(map_attr, info_attr)
        + _btf_events(btf_attr)
        + _test_run_events(test_attr, invalid_test_attr)
        + _prog_load_events(prog_attr)
        + attach_detach_events()
        + percpu_events()
        + delete_batch_events()
        + delete_elem_events()
        + next_key_events()
        + update_elem_events()
        + lookup_events()
        + next_id_events()
        + query_events()
        + task_fd_query_events()
        + uprobe_events()
        + prog_load_fd_array_events()
        + prog_load_func_info_events()
        + prog_load_line_info_events()
        + prog_load_core_relos_events()
    )
