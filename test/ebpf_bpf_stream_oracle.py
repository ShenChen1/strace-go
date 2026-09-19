#!/usr/bin/env python3
import base64

from ebpf_check_support import require, valid_stats_event


ZERO_STATS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)


def _bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _events(events, event_type, command):
    return [
        event
        for event in events
        if event.get("syscall") == "bpf"
        and event.get("event_type") == event_type
        and (event.get("args") or [None])[0] == command
    ]


def _valid_stream_output(section):
    return (
        section.get("kind") == "bytes"
        and section.get("direction") == "out"
        and section.get("arg_index") == 111
        and section.get("probe_ret") == 0
        and 0 < section.get("copied_len", 0) <= 512
        and 0 < section.get("user_len", 0) <= 512
    )


def _has_stream_data(event):
    return any(
        _valid_stream_output(section) and b"stream-data" in _bytes(section)
        for section in event.get("payload_sections") or []
    )


def has_stream_read_output(events):
    enters = _events(events, "enter", 37)
    exits = _events(events, "exit", 37)
    if len(enters) != 3 or len(exits) != 3:
        return False
    if any(event.get("paired_enter") is not True for event in exits):
        return False
    if any(
        section.get("arg_index") == 111
        for event in enters
        for section in event.get("payload_sections") or []
    ):
        return False

    successes = [event for event in exits if event.get("ret", 0) > 0]
    failures = [event for event in exits if event.get("ret", 0) < 0]
    return (
        len(successes) == 1
        and len(failures) == 2
        and _has_stream_data(successes[0])
        and all(_has_stream_data(event) for event in failures)
    )


def check_bpf_stream(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"BPF stream fixture rc={returncode}")
    require("bpf-stream-fixture-ok" in stdout, failures, "BPF stream fixture marker missing")
    require(events, failures, "BPF stream fixture produced no syscall events")
    require(has_stream_read_output(events), failures, "BPF stream success/failure contract missing")
    require(len(stats_events) == 1, failures, "BPF stream stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "BPF stream stats malformed")
        for key in ZERO_STATS:
            require(stats.get(key) == 0, failures, f"BPF stream {key} is non-zero")
    return failures
