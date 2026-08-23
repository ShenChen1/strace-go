#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYCTL_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_keyctl_fixture.c"
)
KEYCTL_ZERO_STATS = (
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


def _operation_events(events, event_type, operation):
    return [
        event
        for event in events
        if event.get("syscall") == "keyctl"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == operation
    ]


def _has_payload(events, expectation):
    event_type, operation, kind, direction, arg_index, marker = expectation
    for event in _operation_events(events, event_type, operation):
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == kind
                and section.get("direction") == direction
                and section.get("arg_index") == arg_index
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) >= len(marker)
                and marker in _section_bytes(section)
            ):
                return True
    return False


def _has_paired_exit(events, operation):
    return any(
        event.get("paired_enter") is True
        for event in _operation_events(events, "exit", operation)
    )


def _failed_events_have_no_output(events):
    return not any(
        event.get("event_type") == "exit"
        and event.get("ret", 0) < 0
        and any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        )
        for event in events
    )


def check_keyctl_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"keyctl fixture rc={returncode}")
    require("keyctl-fixture-ok" in stdout, failures, "keyctl fixture marker missing")
    require(len(stats_events) == 1, failures, "keyctl stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "keyctl stats event is malformed")
        for key in KEYCTL_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"keyctl {key} is non-zero")

    operations = (1, 2, 6, 10, 11, 19, 31)
    for operation in operations:
        require(
            _has_paired_exit(events, operation),
            failures,
            f"keyctl operation {operation} paired exit missing",
        )
    payload_checks = (
        ("enter", 1, "string", "in", 1, b"ebpf-keyctl-session"),
        ("enter", 2, "bytes", "in", 2, b"ebpf-keyctl-update"),
        ("enter", 10, "string", "in", 2, b"user"),
        ("enter", 10, "string", "in", 3, b"ebpf-keyctl-key"),
        ("exit", 6, "bytes", "out", 2, b"ebpf-keyctl-key"),
        ("exit", 11, "bytes", "out", 2, b"ebpf-keyctl-update"),
    )
    for event_type, operation, kind, direction, arg_index, marker in payload_checks:
        require(
            _has_payload(
                events,
                (event_type, operation, kind, direction, arg_index, marker),
            ),
            failures,
            f"keyctl operation {operation} arg {arg_index} payload missing",
        )
    reject_enters = _operation_events(events, "enter", 19)
    require(reject_enters, failures, "keyctl reject enter missing")
    require(
        all(not event.get("payload_sections") for event in reject_enters),
        failures,
        "keyctl reject captured unsupported payload",
    )
    capability_events = _operation_events(events, "exit", 31)
    require(
        any(
            section.get("direction") == "out"
            and section.get("arg_index") == 1
            and section.get("copied_len", 0) > 0
            and _section_bytes(section)
            for event in capability_events
            for section in event.get("payload_sections") or []
        ),
        failures,
        "keyctl capabilities OUT payload missing",
    )
    require(
        _failed_events_have_no_output(events),
        failures,
        "keyctl failure fabricated OUT payload",
    )
    return failures


def run_keyctl_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-keyctl-fixture", (KEYCTL_FIXTURE_SOURCE,)
    )
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=add_key,keyctl,request_key",
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
    failures = check_keyctl_semantic(
        result.returncode,
        result.stdout,
        events,
        parse_stats_events(result.stderr),
    )
    if not failures:
        print(f"=> eBPF keyctl semantic events: {len(events)}")
    return failures
