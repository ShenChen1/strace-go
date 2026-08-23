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


def _has_output_section(events, command, kind, arg_index, marker=b"", ret=None):
    for event in _bpf_events(events, "exit", command):
        if ret is not None and event.get("ret") != ret:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == kind
                and section.get("direction") == "out"
                and section.get("arg_index") == arg_index
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and marker in _section_bytes(section)
            ):
                return True
    return False


def _batch_elem_flags(event):
    for section in event.get("payload_sections") or []:
        if section.get("arg_index") != 1 or section.get("direction") != "in":
            continue
        data = _section_bytes(section)
        if len(data) >= 48:
            return int.from_bytes(data[40:48], "little")
    return None


def has_percpu_map_semantics(events):
    required_updates = (
        (0, b"percpu-no-flags", 17),
        (8, b"percpu-cpu", 16),
        (16, b"percpu-all-cpus", 16),
    )
    for flags, marker, minimum_len in required_updates:
        found = False
        for event in _bpf_events(events, "enter", 26):
            if _batch_elem_flags(event) != flags:
                continue
            for section in event.get("payload_sections") or []:
                if (
                    section.get("direction") == "in"
                    and section.get("arg_index") == 122
                    and section.get("probe_ret") == 0
                    and section.get("user_len", 0) >= minimum_len
                    and section.get("copied_len", 0) > 0
                    and marker in _section_bytes(section)
                ):
                    found = True
                    break
            if found:
                break
        if not found:
            return False

    batch_value = False
    for event in _bpf_events(events, "exit", 24):
        if event.get("ret") not in (0, -2):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "out"
                and section.get("arg_index") == 119
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and section.get("copied_len", 0) <= 512
                and b"percpu-no-flags" in _section_bytes(section)
            ):
                batch_value = True
                break
        if batch_value:
            break
    single_value = _has_output_section(
        events, 1, "bytes", 117, b"percpu-cpu", ret=0
    )
    return batch_value and single_value
