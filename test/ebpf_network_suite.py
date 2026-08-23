#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NETWORK_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_network_fixture.c"
)
NETWORK_PAYLOAD_MARKER = b"ebpf-network-payload"
NETWORK_ZERO_STATS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _has_payload(
    events,
    syscall,
    event_type,
    kind,
    direction,
    arg_index,
    minimum_length,
    marker=None,
    ipv4=False,
):
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != kind
                or section.get("direction") != direction
                or section.get("arg_index") != arg_index
                or section.get("probe_ret") != 0
                or section.get("user_len", 0) < minimum_length
                or section.get("copied_len", 0) < minimum_length
            ):
                continue
            data = _section_bytes(section)
            if len(data) < minimum_length:
                continue
            if marker is not None and marker not in data:
                continue
            if ipv4 and (len(data) < 8 or data[0:2] != b"\x02\x00" or data[4:8] != b"\x7f\x00\x00\x01"):
                continue
            return True
    return False


def _has_successful_exit(events, syscall):
    return any(
        event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("ret", -1) >= 0
        and event.get("paired_enter") is True
        for event in events
    )


def _has_failed_exit(events, syscall):
    return any(
        event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("ret") == -9
        and event.get("failed") is True
        for event in events
    )


def _has_sockaddr_text(events):
    text = " ".join(
        value
        for event in events
        for value in event.get("arg_text") or []
        if isinstance(value, str)
    )
    return "AF_INET" in text and "127.0.0.1" in text


def check_network_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"network fixture rc={returncode}")
    require("network-fixture-ok" in stdout, failures, "network fixture marker missing")
    require(len(stats_events) == 1, failures, "network stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "network stats event is malformed")
        for key in NETWORK_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"network {key} is non-zero")

    for syscall in (
        "bind",
        "connect",
        "accept",
        "accept4",
        "getsockname",
        "getpeername",
        "sendto",
        "recvfrom",
    ):
        require(
            _has_successful_exit(events, syscall),
            failures,
            f"{syscall} successful paired exit missing",
        )
    for syscall in ("connect", "sendto", "recvfrom"):
        require(_has_failed_exit(events, syscall), failures, f"{syscall} EBADF failure missing")

    payload_checks = (
        ("bind", "enter", "struct", "in", 1, 16, None, True, "bind IN sockaddr"),
        ("connect", "enter", "struct", "in", 1, 16, None, True, "connect IN sockaddr"),
        ("accept", "enter", "bytes", "in", 2, 4, None, False, "accept IN socklen"),
        ("accept", "exit", "struct", "out", 1, 16, None, True, "accept OUT sockaddr"),
        ("accept", "exit", "bytes", "out", 2, 4, None, False, "accept OUT socklen"),
        ("accept4", "enter", "bytes", "in", 2, 4, None, False, "accept4 IN socklen"),
        ("accept4", "exit", "struct", "out", 1, 16, None, True, "accept4 OUT sockaddr"),
        ("accept4", "exit", "bytes", "out", 2, 4, None, False, "accept4 OUT socklen"),
        ("getsockname", "exit", "struct", "out", 1, 16, None, True, "getsockname OUT sockaddr"),
        ("getpeername", "exit", "struct", "out", 1, 16, None, True, "getpeername OUT sockaddr"),
        ("sendto", "enter", "bytes", "in", 1, len(NETWORK_PAYLOAD_MARKER), NETWORK_PAYLOAD_MARKER, False, "sendto IN buffer"),
        ("sendto", "enter", "struct", "in", 4, 16, None, True, "sendto IN sockaddr"),
        ("recvfrom", "exit", "bytes", "out", 1, len(NETWORK_PAYLOAD_MARKER), NETWORK_PAYLOAD_MARKER, False, "recvfrom OUT buffer"),
        ("recvfrom", "exit", "struct", "out", 4, 16, None, True, "recvfrom OUT sockaddr"),
        ("recvfrom", "exit", "bytes", "out", 5, 4, None, False, "recvfrom OUT socklen"),
    )
    for syscall, event_type, kind, direction, arg_index, minimum, marker, ipv4, label in payload_checks:
        require(
            _has_payload(
                events,
                syscall,
                event_type,
                kind,
                direction,
                arg_index,
                minimum,
                marker,
                ipv4,
            ),
            failures,
            f"{label} snapshot missing",
        )
    require(_has_sockaddr_text(events), failures, "network sockaddr text missing")
    return failures


def run_network_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-network-fixture", (NETWORK_FIXTURE_SOURCE,)
    )
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=socket,bind,listen,getsockname,connect,accept,accept4,getpeername,sendto,recvfrom,close",
            fixture,
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    events = parse_json_events(result.stderr)
    stats_events = parse_stats_events(result.stderr)
    failures = check_network_semantic(
        result.returncode, result.stdout, events, stats_events
    )
    if not failures:
        print(f"=> eBPF network semantic events: {len(events)}")
    return failures
