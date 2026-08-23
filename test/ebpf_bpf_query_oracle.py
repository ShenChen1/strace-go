#!/usr/bin/env python3
import base64


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _u32(section):
    data = _bytes(section)
    if len(data) < 4:
        return None
    return int.from_bytes(data[:4], "little")


def has_prog_query_output_arrays(events):
    for event in events:
        if (
            event.get("syscall") != "bpf"
            or event.get("event_type") != "exit"
            or (event.get("args") or [None])[0] != 16
            or event.get("ret") != 0
            or event.get("paired_enter") is not True
        ):
            continue
        sections = [
            section
            for section in event.get("payload_sections") or []
            if section.get("direction") == "out"
        ]
        if [section.get("arg_index") for section in sections] != [132, 128, 129, 130, 131]:
            continue
        count = _u32(sections[0])
        if count is None or count == 0:
            continue
        if any(
            section.get("kind") != "bytes"
            or section.get("probe_ret") != 0
            or section.get("user_len") != count * 4
            or section.get("copied_len") != count * 4
            or len(_bytes(section)) != count * 4
            for section in sections[1:]
        ):
            continue
        if _u32(sections[1]) in (None, 0):
            continue
        if all(_u32(section) is not None for section in sections[1:]):
            return True
    return False


def has_prog_attach_detach_lifecycle(events):
    for command in (8, 9):
        if not any(
            event.get("event_type") == "enter"
            and event.get("syscall") == "bpf"
            and (event.get("args") or [None])[0] == command
            and any(
                section.get("direction") == "in"
                and section.get("arg_index") == 1
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                for section in event.get("payload_sections") or []
            )
            for event in events
        ):
            return False
        if not any(
            event.get("event_type") == "exit"
            and event.get("syscall") == "bpf"
            and (event.get("args") or [None])[0] == command
            and event.get("ret", -1) >= 0
            and event.get("paired_enter") is True
            for event in events
        ):
            return False
    return True


def failed_query_has_no_output(events):
    return all(
        not (
            event.get("syscall") == "bpf"
            and event.get("event_type") == "exit"
            and (event.get("args") or [None])[0] == 16
            and event.get("ret", 0) < 0
            and any(
                section.get("direction") == "out"
                for section in event.get("payload_sections") or []
            )
        )
        for event in events
    )
