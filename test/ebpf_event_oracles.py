#!/usr/bin/env python3
import base64
import json
from dataclasses import dataclass


EVENT_FLAG_TRUNCATED = 4


@dataclass(frozen=True)
class StructPayloadSpec:
    syscall: str
    event_type: str
    direction: str
    arg_index: int
    user_len: int


def parse_events(stderr, event_type):
    events = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == event_type:
            events.append(event)
    return events


def parse_json_events(stderr):
    return parse_events(stderr, "syscall")


def parse_lifecycle_events(stderr):
    return parse_events(stderr, "lifecycle")


def parse_stats_events(stderr):
    return parse_events(stderr, "stats")


def parse_ready_events(stderr):
    return parse_events(stderr, "ready")


def payload_section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (ValueError, TypeError):
        return b""


def payload_section_text(section):
    return payload_section_bytes(section).decode("utf-8", errors="ignore")


def has_large_write_truncation(events):
    for event in events:
        if event.get("syscall") != "write":
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "bytes" or section.get("direction") != "in":
                continue
            if section.get("arg_index") != 1:
                continue
            if "ebpf-large-write-" not in payload_section_text(section):
                continue
            copied_len = section.get("copied_len", 0)
            user_len = section.get("user_len", 0)
            has_flag = (event.get("event_flags", 0) & EVENT_FLAG_TRUNCATED) != 0
            return has_flag and 0 < copied_len < user_len
    return False


def has_path_section(events, syscall, arg_index, path_text):
    for event in events:
        if event.get("syscall") != syscall:
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "string" or section.get("direction") != "in":
                continue
            if section.get("arg_index") == arg_index and path_text in payload_section_text(section):
                return True
    return False


def has_openat_path_section(events, path_text):
    return has_path_section(events, "openat", 1, path_text)


def has_exec_payload_sections(events):
    for event in events:
        if event.get("syscall") != "execve" or event.get("event_type") != "enter":
            continue
        has_args = False
        has_path = False
        for section in event.get("payload_sections") or []:
            if section.get("kind") == "exec_args" and section.get("direction") == "in" and section.get("arg_index") == 1:
                data = payload_section_bytes(section)
                has_args = len(data) >= 4 and data[0:4] == b"CEXE"
            if section.get("kind") == "string" and section.get("direction") == "in" and section.get("arg_index") == 0:
                has_path = True
        if has_args and has_path:
            return True
    return False


def has_clock_payload_section(events):
    return has_struct_payload_section(events, "clock_gettime", 1, 16)


def has_gettimeofday_payload_sections(events):
    return (
        has_struct_payload_section(events, "gettimeofday", 0, 16)
        and has_struct_payload_section(events, "gettimeofday", 1, 8)
    )


def has_struct_payload_section_with_direction(events, spec):
    for event in events:
        if event.get("syscall") != spec.syscall or event.get("event_type") != spec.event_type:
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "struct" or section.get("direction") != spec.direction:
                continue
            if section.get("arg_index") != spec.arg_index:
                continue
            return (
                section.get("user_len") == spec.user_len
                and section.get("copied_len") == spec.user_len
                and len(payload_section_bytes(section)) == spec.user_len
            )
    return False


def has_struct_payload_section(events, syscall, arg_index, user_len):
    return has_struct_payload_section_with_direction(
        events, StructPayloadSpec(syscall, "exit", "out", arg_index, user_len)
    )


def has_fstat_payload_section(events):
    return has_struct_payload_section(events, "fstat", 1, 144)


def has_stat_payload_section(events, syscall, arg_index):
    return has_struct_payload_section(events, syscall, arg_index, 144)


def has_fstatfs_payload_section(events):
    return has_struct_payload_section(events, "fstatfs", 1, 120)


def has_statfs_payload_section(events):
    return has_struct_payload_section(events, "statfs", 1, 120)


def has_bytes_payload_section(events, syscall, arg_index, text):
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != "exit":
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "bytes" or section.get("direction") != "out":
                continue
            if section.get("arg_index") == arg_index:
                return text in payload_section_text(section)
    return False


def has_sendmsg_cmsg_section(events):
    for event in events:
        if event.get("syscall") != "sendmsg" or event.get("event_type") != "enter":
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "cmsg" or section.get("direction") != "in":
                continue
            if section.get("arg_index") != 1:
                continue
            data = payload_section_bytes(section)
            return (
                section.get("user_len", 0) >= 16
                and section.get("copied_len", 0) >= 16
                and len(data) >= 16
            )
    return False
