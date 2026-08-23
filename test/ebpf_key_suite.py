#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FIXTURE_SOURCE = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_key_fixture.c")
KEY_ZERO_STATS = (
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


def _has_payload(events, expectation):
    syscall, event_type, kind, direction, arg_index, marker, label = expectation
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
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


def _has_paired_exit(events, syscall):
    return any(
        event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("paired_enter") is True
        for event in events
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


def check_key_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"key fixture rc={returncode}")
    require("key-fixture-ok" in stdout, failures, "key fixture marker missing")
    require(len(stats_events) == 1, failures, "key stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "key stats event is malformed")
        for key in KEY_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"key {key} is non-zero")

    for syscall in ("add_key", "request_key"):
        require(
            _has_paired_exit(events, syscall),
            failures,
            f"{syscall} paired exit missing",
        )
    payload_checks = (
        ("add_key", "enter", "string", "in", 0, b"user", "add_key type"),
        ("add_key", "enter", "string", "in", 1, b"ebpf-key-add", "add_key description"),
        ("add_key", "enter", "bytes", "in", 2, b"ebpf-key-payload", "add_key payload"),
        ("request_key", "enter", "string", "in", 0, b"user", "request_key type"),
        ("request_key", "enter", "string", "in", 1, b"ebpf-key-request", "request_key description"),
        ("request_key", "enter", "string", "in", 2, b"ebpf-key-callout", "request_key callout"),
    )
    for expectation in payload_checks:
        require(_has_payload(events, expectation), failures, f"{expectation[-1]} missing")
    require(_failed_events_have_no_output(events), failures, "key failure fabricated OUT payload")
    return failures


def run_key_semantic(wrapper, root):
    fixture = build_named_fixture("strace-go-ebpf-key-fixture", (KEY_FIXTURE_SOURCE,))
    result = subprocess.run(
        [wrapper, "--event-format=json", "-e", "trace=add_key,request_key", fixture],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    failures = check_key_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print(f"=> eBPF key semantic events: {len(parse_json_events(result.stderr))}")
    return failures
