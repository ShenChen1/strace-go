#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLL_SELECT_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_poll_select_fixture.c"
)
POLL_SELECT_ZERO_STATS = (
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


def _has_section(events, syscall, event_type, kind, direction, arg_index, minimum):
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != kind
                or section.get("direction") != direction
                or section.get("arg_index") != arg_index
                or section.get("probe_ret") != 0
                or section.get("user_len", 0) < minimum
                or section.get("copied_len", 0) < minimum
            ):
                continue
            if len(_section_bytes(section)) >= minimum:
                return True
    return False


def _has_ready_poll_exit(events, syscall):
    for event in events:
        if (
            event.get("syscall") != syscall
            or event.get("event_type") != "exit"
            or event.get("ret") != 1
            or event.get("paired_enter") is not True
        ):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != "struct"
                or section.get("direction") != "out"
                or section.get("arg_index") != 0
            ):
                continue
            data = _section_bytes(section)
            if len(data) >= 8 and int.from_bytes(data[6:8], "little") & 1:
                return True
    return False


def _has_ready_select_exit(events, syscall):
    for event in events:
        if (
            event.get("syscall") != syscall
            or event.get("event_type") != "exit"
            or event.get("ret") != 1
            or event.get("paired_enter") is not True
        ):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == "out"
                and section.get("arg_index") == 1
                and any(_section_bytes(section))
            ):
                return True
    return False


def _has_failed_exit(events, syscall):
    return any(
        event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("ret") == -14
        and event.get("failed") is True
        and event.get("paired_enter") is True
        for event in events
    )


def _has_failed_output(events):
    return any(
        event.get("syscall") in {"poll", "ppoll", "select", "pselect6"}
        and event.get("event_type") == "exit"
        and event.get("ret") == -14
        and any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        )
        for event in events
    )


def check_poll_select_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"poll-select fixture rc={returncode}")
    require(
        "poll-select-fixture-ok" in stdout,
        failures,
        "poll-select fixture marker missing",
    )
    require(len(stats_events) == 1, failures, "poll-select stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "poll-select stats event is malformed")
        for key in POLL_SELECT_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"poll-select {key} is non-zero")

    for syscall in ("poll", "ppoll", "select", "pselect6"):
        require(
            _has_failed_exit(events, syscall),
            failures,
            f"{syscall} EFAULT failure missing",
        )
    require(_has_ready_poll_exit(events, "poll"), failures, "poll ready exit missing")
    require(_has_ready_poll_exit(events, "ppoll"), failures, "ppoll ready exit missing")
    require(_has_ready_select_exit(events, "select"), failures, "select ready exit missing")
    require(_has_ready_select_exit(events, "pselect6"), failures, "pselect6 ready exit missing")

    payload_checks = (
        ("poll", "enter", "struct", "in", 0, 8, "poll IN fdset"),
        ("poll", "exit", "struct", "out", 0, 8, "poll OUT fdset"),
        ("ppoll", "enter", "struct", "in", 0, 8, "ppoll IN fdset"),
        ("ppoll", "enter", "struct", "in", 2, 16, "ppoll IN timeout"),
        ("ppoll", "enter", "struct", "in", 3, 8, "ppoll IN sigmask"),
        ("ppoll", "exit", "struct", "out", 0, 8, "ppoll OUT fdset"),
        ("ppoll", "exit", "struct", "out", 2, 16, "ppoll OUT timeout"),
        ("select", "enter", "bytes", "in", 1, 1, "select IN fdset"),
        ("select", "enter", "struct", "in", 4, 16, "select IN timeout"),
        ("select", "exit", "bytes", "out", 1, 1, "select OUT fdset"),
        ("select", "exit", "struct", "out", 4, 16, "select OUT timeout"),
        ("pselect6", "enter", "bytes", "in", 1, 1, "pselect6 IN fdset"),
        ("pselect6", "enter", "struct", "in", 4, 16, "pselect6 IN timeout"),
        ("pselect6", "enter", "struct", "in", 5, 16, "pselect6 IN wrapper"),
        ("pselect6", "enter", "struct", "in", 6, 8, "pselect6 IN sigmask"),
        ("pselect6", "exit", "bytes", "out", 1, 1, "pselect6 OUT fdset"),
        ("pselect6", "exit", "struct", "out", 4, 16, "pselect6 OUT timeout"),
    )
    for syscall, event_type, kind, direction, arg_index, minimum, label in payload_checks:
        require(
            _has_section(events, syscall, event_type, kind, direction, arg_index, minimum),
            failures,
            f"{label} missing",
        )
    text = " ".join(
        value
        for event in events
        for value in event.get("arg_text") or []
        if isinstance(value, str)
    )
    require("POLLIN" in text, failures, "poll ready flag text missing")
    require("sigmask=" in text, failures, "pselect6 sigmask text missing")
    require(not _has_failed_output(events), failures, "poll-select failure fabricated OUT payload")
    return failures


def run_poll_select_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-poll-select-fixture", (POLL_SELECT_FIXTURE_SOURCE,)
    )
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=poll,ppoll,select,pselect6,close",
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
    failures = check_poll_select_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print(
            f"=> eBPF poll/select semantic events: {len(parse_json_events(result.stderr))}"
        )
    return failures
