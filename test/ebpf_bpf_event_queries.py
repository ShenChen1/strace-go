#!/usr/bin/env python3
import base64


def section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def bpf_events(events, event_type, command):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == command
    ]


def has_section(events, command, kind, direction, arg_index, marker=b""):
    for event in bpf_events(events, "enter", command):
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == kind
                and section.get("direction") == direction
                and section.get("arg_index") == arg_index
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and marker in section_bytes(section)
            ):
                return True
    return False


def has_output_section(events, command, kind, arg_index, marker=b"", ret=None):
    for event in bpf_events(events, "exit", command):
        if ret is not None and event.get("ret") != ret:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == kind
                and section.get("direction") == "out"
                and section.get("arg_index") == arg_index
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and section.get("user_len", 0) <= 512
                and marker in section_bytes(section)
            ):
                return True
    return False


def has_test_run_output_order(events):
    for event in bpf_events(events, "exit", 10):
        if event.get("ret") != 0:
            continue
        output_args = [
            section.get("arg_index")
            for section in event.get("payload_sections") or []
            if section.get("direction") == "out"
        ]
        if output_args[:2] == [115, 116]:
            return True
    return False


def has_map_batch_output_order(events):
    for command in (24, 25):
        for event in bpf_events(events, "exit", command):
            if event.get("ret") != 0:
                continue
            output_args = [
                section.get("arg_index")
                for section in event.get("payload_sections") or []
                if section.get("direction") == "out"
            ]
            if output_args[:3] == [120, 118, 119]:
                return True
    return False


def has_map_batch_partial_output(events):
    for command in (24, 25):
        for event in bpf_events(events, "exit", command):
            if event.get("ret") != -2:
                continue
            sections = [
                section
                for section in event.get("payload_sections") or []
                if section.get("direction") == "out"
            ]
            if [section.get("arg_index") for section in sections] != [120, 118, 119]:
                continue
            if all(
                section.get("kind") == "bytes"
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and section.get("user_len", 0) <= 512
                for section in sections
            ):
                return True
    return False


def has_map_batch_input_order(events):
    for event in bpf_events(events, "enter", 26):
        sections = [
            section
            for section in event.get("payload_sections") or []
            if section.get("direction") == "in"
            and section.get("arg_index") in (121, 122)
        ]
        if [section.get("arg_index") for section in sections] != [121, 122]:
            continue
        if all(
            section.get("kind") == "bytes"
            and section.get("probe_ret") == 0
            and section.get("copied_len", 0) > 0
            and section.get("user_len", 0) <= 512
            for section in sections
        ) and b"update-key!" in section_bytes(sections[0]) and b"update-value!" in section_bytes(sections[1]):
            return True
    return False


def has_hash_batch_cursor_width(events):
    for command in (24, 25):
        for event in bpf_events(events, "exit", command):
            if event.get("ret") not in (0, -2):
                continue
            sections = [
                section
                for section in event.get("payload_sections") or []
                if section.get("direction") == "out"
            ]
            if [section.get("arg_index") for section in sections] != [120, 118, 119]:
                continue
            by_arg = {section.get("arg_index"): section for section in sections}
            if (
                by_arg[120].get("user_len") == 4
                and by_arg[120].get("copied_len") == 4
                and by_arg[118].get("user_len") == 1
                and by_arg[118].get("copied_len") == 1
                and by_arg[119].get("user_len") == 16
                and by_arg[119].get("copied_len") > 0
                and b"cursor-value" in section_bytes(by_arg[119])
            ):
                return True
    return False


def has_paired_exit(events, command):
    return any(
        event.get("paired_enter") is True
        for event in bpf_events(events, "exit", command)
    )


def has_failed_exit(events, command):
    return any(
        event.get("ret", 0) < 0
        for event in bpf_events(events, "exit", command)
    )


def failed_events_have_no_output(events):
    for event in events:
        if (
            event.get("event_type") != "exit"
            or event.get("syscall") != "bpf"
            or event.get("ret", 0) >= 0
        ):
            continue
        output_sections = [
            section
            for section in event.get("payload_sections") or []
            if section.get("direction") == "out"
        ]
        if not output_sections:
            continue
        command = event.get("args", [None])[0]
        if command in (24, 25) and event.get("ret") == -2:
            allowed_output_args = {120, 118, 119}
            if any(
                section.get("kind") != "bytes"
                or section.get("arg_index") not in allowed_output_args
                or section.get("probe_ret") != 0
                or section.get("copied_len", 0) <= 0
                or section.get("copied_len", 0) > 512
                for section in output_sections
            ):
                return False
            continue
        allowed_output_args = {5: 102, 18: 114}
        if command not in allowed_output_args:
            return False
        if any(
            section.get("kind") != "bytes"
            or section.get("arg_index") != allowed_output_args[command]
            or section.get("probe_ret") != 0
            or section.get("copied_len", 0) <= 0
            or section.get("user_len", 0) > 256
            for section in output_sections
        ):
            return False
    return True
