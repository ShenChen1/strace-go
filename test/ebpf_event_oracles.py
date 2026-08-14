#!/usr/bin/env python3
import base64
import json
from dataclasses import dataclass


EVENT_FLAG_TRUNCATED = 4
EVENT_FLAG_EXIT_FRAGMENT = 8
FD_STATE_ARG_INDEX = 0xffff
FD_STATE_SNAPSHOT_SIZE = 48


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


def parse_phase_events(stderr):
    return parse_events(stderr, "phase")


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


def has_ordered_event_sections(
    events, syscall, event_type, kind, direction, expected_arg_indices
):
    expected = list(expected_arg_indices)
    if not expected:
        return False
    observed = []
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
        if event_type == "exit" and event.get("event_flags", 0) & EVENT_FLAG_EXIT_FRAGMENT:
            continue
        observed.extend(
            section.get("arg_index")
            for section in event.get("payload_sections") or []
            if section.get("kind") == kind
            and section.get("direction") == direction
        )
    return observed == expected


def has_ordered_merged_exit_sections(
    events, syscall, kind, direction, expected_arg_indices
):
    return any(
        has_ordered_event_sections(
            [event], syscall, "exit", kind, direction, expected_arg_indices
        )
        for event in events
        if event.get("event_type") == "exit"
        and (event.get("event_flags", 0) & EVENT_FLAG_EXIT_FRAGMENT) == 0
    )


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


def _has_valid_fd_state_section(event):
    if event.get("event_type") != "exit" or event.get("ret", -1) < 0:
        return False
    for section in event.get("payload_sections") or []:
        if (
            section.get("kind") != "fd_state"
            or section.get("direction") != "out"
            or section.get("arg_index") != FD_STATE_ARG_INDEX
            or section.get("user_len") != FD_STATE_SNAPSHOT_SIZE
            or section.get("copied_len") != FD_STATE_SNAPSHOT_SIZE
            or section.get("probe_ret") != 0
        ):
            continue
        data = payload_section_bytes(section)
        if len(data) != FD_STATE_SNAPSHOT_SIZE:
            continue
        snapshot_fd = int.from_bytes(data[0:4], "little", signed=True)
        flags = int.from_bytes(data[4:8], "little")
        inode = int.from_bytes(data[32:40], "little")
        if snapshot_fd == event.get("ret") and (flags & 3) == 3 and inode > 0:
            return True
    return False


def _has_fd_state_section_for_syscalls(events, syscall_names):
    return any(
        event.get("syscall") in syscall_names and _has_valid_fd_state_section(event)
        for event in events
    )


def _has_path_and_fd_state_event(event, syscall):
    if event.get("syscall") != syscall:
        return False
    path_arg = 1 if syscall in {"openat", "openat2"} else 0
    has_path = any(
        section.get("kind") == "string"
        and section.get("direction") == "in"
        and section.get("arg_index") == path_arg
        and section.get("probe_ret") == 0
        and section.get("copied_len", 0) > 0
        for section in event.get("payload_sections") or []
    )
    return has_path and _has_valid_fd_state_section(event)


def has_path_and_fd_state_for_syscall(events, syscall):
    return any(_has_path_and_fd_state_event(event, syscall) for event in events)


def has_open_family_path_and_fd_state(events):
    return any(
        has_path_and_fd_state_for_syscall(events, syscall)
        for syscall in ("open", "openat", "creat")
    )


def has_openat2_path_how_and_fd_state(events):
    for event in events:
        if not _has_path_and_fd_state_event(event, "openat2"):
            continue
        has_how = any(
            section.get("kind") == "struct"
            and section.get("direction") == "in"
            and section.get("arg_index") == 2
            and section.get("user_len", 0) >= 24
            and section.get("copied_len", 0) >= 24
            and section.get("probe_ret") == 0
            for section in event.get("payload_sections") or []
        )
        if has_how:
            return True
    return False


def has_fd_state_section(events):
    return _has_fd_state_section_for_syscalls(
        events, {"open", "openat", "openat2", "open_tree", "creat"}
    )


def has_fd_state_for_syscall(events, syscall_name):
    return _has_fd_state_section_for_syscalls(events, {syscall_name})


def has_dup_fd_state_sections(events):
    return all(
        _has_fd_state_section_for_syscalls(events, {syscall})
        for syscall in ("dup", "dup2", "dup3")
    )


def _has_fd_array_fd_state_sections_for_syscall(events, syscall_name):
    for event in events:
        if event.get("event_type") != "exit" or event.get("syscall") != syscall_name:
            continue
        if event.get("ret", -1) != 0:
            continue
        valid_fds = set()
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != "fd_state"
                or section.get("direction") != "out"
                or section.get("arg_index") != FD_STATE_ARG_INDEX
                or section.get("user_len") != FD_STATE_SNAPSHOT_SIZE
                or section.get("copied_len") != FD_STATE_SNAPSHOT_SIZE
                or section.get("probe_ret") != 0
            ):
                continue
            data = payload_section_bytes(section)
            if len(data) != FD_STATE_SNAPSHOT_SIZE:
                continue
            snapshot_fd = int.from_bytes(data[0:4], "little", signed=True)
            flags = int.from_bytes(data[4:8], "little")
            inode = int.from_bytes(data[32:40], "little")
            if snapshot_fd >= 0 and (flags & 3) == 3 and inode > 0:
                valid_fds.add(snapshot_fd)
        if len(valid_fds) >= 2:
            return True
    return False


def has_fd_array_fd_state_sections(events):
    return all(
        _has_fd_array_fd_state_sections_for_syscall(events, syscall)
        for syscall in ("pipe", "pipe2", "socketpair")
    )


def has_fcntl_fd_state_for_command(events, command):
    for event in events:
        args = event.get("args") or []
        if (
            event.get("event_type") != "exit"
            or event.get("syscall") != "fcntl"
            or event.get("ret", -1) < 0
            or len(args) < 2
            or args[1] != command
        ):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != "fd_state"
                or section.get("direction") != "out"
                or section.get("arg_index") != FD_STATE_ARG_INDEX
                or section.get("user_len") != FD_STATE_SNAPSHOT_SIZE
                or section.get("copied_len") != FD_STATE_SNAPSHOT_SIZE
                or section.get("probe_ret") != 0
            ):
                continue
            data = payload_section_bytes(section)
            if len(data) != FD_STATE_SNAPSHOT_SIZE:
                continue
            snapshot_fd = int.from_bytes(data[0:4], "little", signed=True)
            flags = int.from_bytes(data[4:8], "little")
            inode = int.from_bytes(data[32:40], "little")
            if snapshot_fd == event.get("ret") and (flags & 3) == 3 and inode > 0:
                return True
    return False


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
