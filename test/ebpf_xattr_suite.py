#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
XATTR_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_xattr_fixture.c"
)
XATTR_PATH_MARKER = b"strace-go-ebpf-xattr-"
XATTR_NAME_MARKER = b"user.fixture"
XATTR_VALUE_MARKER = b"xattr-value"
XATTR_ZERO_STATS = (
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


def _has_payload(events, syscall, event_type, kind, direction, arg_index, marker):
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != kind
                or section.get("direction") != direction
                or section.get("arg_index") != arg_index
                or section.get("probe_ret") != 0
                or section.get("copied_len", 0) < len(marker)
                or section.get("user_len", 0) < len(marker)
            ):
                continue
            if marker in _section_bytes(section):
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


def _has_failed_get(events):
    return any(
        event.get("syscall") == "getxattr"
        and event.get("event_type") == "exit"
        and event.get("ret") == -61
        and event.get("failed") is True
        and event.get("paired_enter") is True
        for event in events
    )


def _failed_get_has_output(events):
    return any(
        event.get("syscall") == "getxattr"
        and event.get("event_type") == "exit"
        and event.get("ret") == -61
        and any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        )
        for event in events
    )


def check_xattr_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"xattr fixture rc={returncode}")
    require("xattr-fixture-ok" in stdout, failures, "xattr fixture marker missing")
    require(len(stats_events) == 1, failures, "xattr stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "xattr stats event is malformed")
        for key in XATTR_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"xattr {key} is non-zero")

    for syscall in ("setxattr", "getxattr", "listxattr", "removexattr"):
        require(
            _has_successful_exit(events, syscall),
            failures,
            f"{syscall} successful paired exit missing",
        )
    require(
        _has_payload(events, "setxattr", "enter", "string", "in", 0, XATTR_PATH_MARKER),
        failures,
        "setxattr IN path missing",
    )
    require(
        _has_payload(events, "setxattr", "enter", "string", "in", 1, XATTR_NAME_MARKER),
        failures,
        "setxattr IN name missing",
    )
    require(
        _has_payload(events, "setxattr", "enter", "bytes", "in", 2, XATTR_VALUE_MARKER),
        failures,
        "setxattr IN value missing",
    )
    require(
        _has_payload(events, "getxattr", "exit", "bytes", "out", 2, XATTR_VALUE_MARKER),
        failures,
        "getxattr OUT value missing",
    )
    require(
        _has_payload(events, "listxattr", "exit", "bytes", "out", 1, XATTR_NAME_MARKER),
        failures,
        "listxattr OUT list missing",
    )
    require(
        _has_payload(events, "removexattr", "enter", "string", "in", 1, XATTR_NAME_MARKER),
        failures,
        "removexattr IN name missing",
    )
    require(_has_failed_get(events), failures, "getxattr ENODATA failure missing")
    require(not _failed_get_has_output(events), failures, "xattr failure fabricated OUT payload")
    return failures


def run_xattr_semantic(wrapper, root):
    fixture = build_named_fixture("strace-go-ebpf-xattr-fixture", (XATTR_FIXTURE_SOURCE,))
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=setxattr,getxattr,listxattr,removexattr",
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
    failures = check_xattr_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print(f"=> eBPF xattr semantic events: {len(parse_json_events(result.stderr))}")
    return failures
