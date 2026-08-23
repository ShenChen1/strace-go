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


def has_get_next_key(events):
    keyed_input = False
    null_input = False
    for event in _bpf_events(events, "enter", 4):
        sections = event.get("payload_sections") or []
        for section in sections:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "in"
                and section.get("arg_index") == 124
                and section.get("probe_ret") == 0
                and section.get("user_len") == 4
                and section.get("copied_len") == 4
                and _section_bytes(section)[:4] == b"\x00\x00\x00\x00"
            ):
                keyed_input = True
        attr = next(
            (
                section
                for section in sections
                if section.get("direction") == "in"
                and section.get("arg_index") == 1
            ),
            None,
        )
        if attr is not None and len(_section_bytes(attr)) >= 16:
            null_input = null_input or int.from_bytes(_section_bytes(attr)[8:16], "little") == 0

    output = any(
        section.get("kind") == "bytes"
        and section.get("direction") == "out"
        and section.get("arg_index") == 125
        and section.get("probe_ret") == 0
        and section.get("user_len") == 4
        and section.get("copied_len") == 4
        and _section_bytes(section)[:4] == b"\x01\x00\x00\x00"
        for event in _bpf_events(events, "exit", 4)
        if event.get("ret") == 0 and event.get("paired_enter") is True
        for section in event.get("payload_sections") or []
    )
    failed_without_output = any(
        event.get("ret", 0) < 0
        and event.get("paired_enter") is True
        and not any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        )
        for event in _bpf_events(events, "exit", 4)
    )
    return keyed_input and null_input and output and failed_without_output
