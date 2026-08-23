#!/usr/bin/env python3
import base64


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _bpf_events(events, event_type, command):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == command
    ]


def has_delete_batch_keys(events):
    for event in _bpf_events(events, "enter", 27):
        sections = event.get("payload_sections") or []
        keys = [
            section
            for section in sections
            if section.get("direction") == "in" and section.get("arg_index") == 121
        ]
        if not keys:
            continue
        if any(
            section.get("direction") == direction
            and section.get("arg_index") in (119, 122)
            for section in sections
            for direction in ("in", "out")
        ):
            continue
        if any(
            section.get("kind") == "bytes"
            and section.get("probe_ret") == 0
            and section.get("copied_len", 0) > 0
            and b"\x00\x00\x00\x00" in _section_bytes(section)
            for section in keys
        ):
            return True
    return False


def has_delete_elem_key(events):
    success_key = False
    for event in _bpf_events(events, "enter", 3):
        sections = event.get("payload_sections") or []
        if any(section.get("direction") == "out" for section in sections):
            continue
        if any(
            section.get("kind") == "bytes"
            and section.get("direction") == "in"
            and section.get("arg_index") == 123
            and section.get("probe_ret") == 0
            and section.get("copied_len", 0) == 4
            and _section_bytes(section)[:4] == b"\x07\x00\x00\x00"
            for section in sections
        ):
            success_key = True
            break
    if not success_key:
        return False
    exits = _bpf_events(events, "exit", 3)
    return any(event.get("paired_enter") is True and event.get("ret") == 0 for event in exits) and any(
        event.get("ret", 0) < 0
        and not any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        )
        for event in exits
    )
