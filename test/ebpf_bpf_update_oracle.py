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


def has_update_elem_inputs(events):
    success = False
    failed = False
    for event in _bpf_events(events, "enter", 2):
        sections = event.get("payload_sections") or []
        inputs = [
            section
            for section in sections
            if section.get("direction") == "in"
            and section.get("arg_index") in (126, 127)
        ]
        if [section.get("arg_index") for section in inputs] == [126, 127]:
            if (
                all(
                    section.get("kind") == "bytes"
                    and section.get("probe_ret") == 0
                    and section.get("copied_len", 0) > 0
                    for section in inputs
                )
                and _section_bytes(inputs[0])[:4] == b"\x00\x00\x00\x00"
                and b"map-value" in _section_bytes(inputs[1])
            ):
                success = True
        if any(
            section.get("arg_index") in (126, 127)
            and section.get("direction") == "in"
            and section.get("probe_ret", 0) < 0
            for section in sections
        ):
            failed = True
    paired_failure = any(
        event.get("paired_enter") is True and event.get("ret", 0) < 0
        for event in _bpf_events(events, "exit", 2)
    )
    return success and failed and paired_failure


def has_large_update_elem_input(events):
    marker = b"large-map-value"
    for event in _bpf_events(events, "enter", 2):
        for section in event.get("payload_sections") or []:
            if (
                section.get("arg_index") == 127
                and section.get("direction") == "in"
                and section.get("probe_ret") == 0
                and section.get("user_len") == 64
                and section.get("copied_len", 0) > 20
                and marker in _section_bytes(section)
            ):
                return True
    return False
