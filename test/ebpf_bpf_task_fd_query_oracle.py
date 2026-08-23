#!/usr/bin/env python3
import base64


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _u32(section, offset):
    data = _bytes(section)
    if len(data) < offset + 4:
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def has_task_fd_query_output(events):
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "exit"
            or (event.get("args") or [None])[0] != 20
            or event.get("ret") != 0
            or event.get("paired_enter") is not True
        ):
            continue
        sections = {
            section.get("arg_index"): section
            for section in event.get("payload_sections") or []
            if section.get("direction") == "out"
        }
        attr = sections.get(138)
        string = sections.get(137)
        if not attr or not string:
            continue
        if (
            attr.get("kind") != "bytes"
            or attr.get("probe_ret") != 0
            or attr.get("copied_len") != 64
            or _u32(attr, 12) != 16
            or (_u32(attr, 24) or 0) == 0
            or _u32(attr, 28) != 1
        ):
            continue
        if (
            string.get("kind") == "string"
            and string.get("probe_ret") == 0
            and 0 < string.get("copied_len", 0) <= 512
            and b"sys_enter_getpid" in _bytes(string)
        ):
            return True
    return False


def failed_task_fd_query_has_no_output(events):
    return all(
        not (
            event.get("syscall") == "bpf"
            and event.get("event_type") == "exit"
            and (event.get("args") or [None])[0] == 20
            and event.get("ret", 0) < 0
            and any(
                section.get("direction") == "out"
                for section in event.get("payload_sections") or []
            )
        )
        for event in events
    )
