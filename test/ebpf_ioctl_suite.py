#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IOCTL_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_ioctl_fixture.c"
)
IOCTL_EXPECTED_AVAILABLE = 17
IOCTL_ZERO_STATS = (
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


def _has_section(events, event_type, direction, value=None):
    for event in events:
        if event.get("syscall") != "ioctl" or event.get("event_type") != event_type:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "bytes"
                and section.get("direction") == direction
                and section.get("arg_index") == 2
                and section.get("user_len") == 4
                and section.get("copied_len") == 4
                and section.get("probe_ret") == 0
            ):
                data = _section_bytes(section)
                if len(data) == 4 and (value is None or int.from_bytes(data, "little") == value):
                    return True
    return False


def _has_successful_exit(events):
    return any(
        event.get("syscall") == "ioctl"
        and event.get("event_type") == "exit"
        and event.get("ret") == 0
        and event.get("paired_enter") is True
        for event in events
    )


def _has_failed_exit(events):
    return any(
        event.get("syscall") == "ioctl"
        and event.get("event_type") == "exit"
        and event.get("ret") == -9
        and event.get("failed") is True
        for event in events
    )


def check_ioctl_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"ioctl fixture rc={returncode}")
    require("ioctl-fixture-ok" in stdout, failures, "ioctl fixture marker missing")
    require(len(stats_events) == 1, failures, "ioctl stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "ioctl stats event is malformed")
        for key in IOCTL_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"ioctl {key} is non-zero")

    require(_has_successful_exit(events), failures, "ioctl successful paired exit missing")
    require(_has_failed_exit(events), failures, "ioctl EBADF failure missing")
    require(_has_section(events, "enter", "in"), failures, "ioctl IN payload missing")
    require(
        _has_section(events, "exit", "out", IOCTL_EXPECTED_AVAILABLE),
        failures,
        "ioctl OUT payload missing",
    )
    failed_events = [
        event
        for event in events
        if event.get("syscall") == "ioctl"
        and event.get("event_type") == "exit"
        and event.get("ret") == -9
    ]
    require(
        not any(
            section.get("direction") == "out"
            for event in failed_events
            for section in event.get("payload_sections") or []
        ),
        failures,
        "ioctl failure fabricated OUT payload",
    )
    text = " ".join(
        value
        for event in events
        for value in event.get("arg_text") or []
        if isinstance(value, str)
    )
    require("FIONREAD" in text, failures, "ioctl command text missing")
    require("[17]" in text, failures, "ioctl decoded output value missing")
    return failures


def run_ioctl_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-ioctl-fixture", (IOCTL_FIXTURE_SOURCE,)
    )
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=pipe,pipe2,write,ioctl,close",
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
    failures = check_ioctl_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print("=> eBPF ioctl semantic passed")
    return failures
