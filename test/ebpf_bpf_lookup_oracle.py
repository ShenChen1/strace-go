#!/usr/bin/env python3
import base64


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def has_lookup_key_inputs(events):
    found = set()
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "enter"
            or (event.get("args") or [None])[0] not in (1, 21)
        ):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "in"
                and section.get("arg_index") == 139
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and section.get("user_len", 0) <= 512
                and _bytes(section)
            ):
                found.add(event["args"][0])
    return found == {1, 21}


def has_failed_lookup_key_probe_failure(events):
    failed_calls = {
        (
            event.get("args", [None, None])[0],
            event.get("args", [None, None])[1],
        )
        for event in events
        if (
            event.get("syscall") == "bpf"
            and event.get("event_type") == "exit"
            and event.get("args", [None])[0] in (1, 21)
            and event.get("ret", 0) < 0
        )
    }
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "enter"
            or (
                event.get("args", [None, None])[0],
                event.get("args", [None, None])[1],
            ) not in failed_calls
        ):
            continue
        for section in event.get("payload_sections") or []:
            if section.get("arg_index") == 139 and section.get("probe_ret", 0) < 0:
                return True
    return False
