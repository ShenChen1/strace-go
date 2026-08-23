#!/usr/bin/env python3
import base64


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def has_uprobe_multi_input_sections(events):
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "enter"
            or (event.get("args") or [None])[0] != 28
        ):
            continue
        attr = event.get("payload_sections") or []
        if not any(section.get("arg_index") == 1 for section in attr):
            continue
        sections = {
            section.get("arg_index"): section
            for section in attr
            if section.get("direction") == "in"
        }
        path = sections.get(133)
        offsets = sections.get(134)
        cookies = sections.get(136)
        if not path or not offsets or not cookies:
            continue
        if path.get("kind") != "string" or b"bpf-fixture" not in _bytes(path):
            continue
        if any(
            section.get("kind") != "bytes"
            or section.get("probe_ret") != 0
            or section.get("copied_len", 0) != 8
            or section.get("user_len") != 8
            for section in (offsets, cookies)
        ):
            continue
        return True
    return False


def has_uprobe_multi_failed_event(events):
    return any(
        event.get("syscall") == "bpf"
        and event.get("event_type") == "exit"
        and (event.get("args") or [None])[0] == 28
        and event.get("ret", 0) < 0
        and event.get("paired_enter") is True
        for event in events
    )
