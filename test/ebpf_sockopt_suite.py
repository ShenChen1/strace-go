#!/usr/bin/env python3
import base64
import os
import subprocess
import tempfile

from ebpf_event_oracles import parse_json_events, parse_stats_events


def _require(condition, failures, message):
    if not condition:
        failures.append(message)


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (ValueError, TypeError):
        return b""


def _sections(events, syscall, event_type, direction, arg_index):
    return [
        section
        for event in events
        if event.get("syscall") == syscall
        and event.get("event_type") == event_type
        for section in event.get("payload_sections") or []
        if section.get("kind") == "bytes"
        and section.get("direction") == direction
        and section.get("arg_index") == arg_index
    ]


def _build_fixture(root, output):
    source = os.path.join(root, "test", "fixtures", "ebpf_sockopt_fixture.c")
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-o", output, source],
        check=True,
    )
    os.chmod(output, 0o755)


def run_sockopt_semantic(wrapper, root):
    failures = []
    with tempfile.TemporaryDirectory(prefix="strace-go-sockopt-") as directory:
        fixture = os.path.join(directory, "fixture")
        _build_fixture(root, fixture)
        result = subprocess.run(
            [wrapper, "--event-format=json", "-e", "trace=setsockopt,getsockopt", fixture],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            timeout=30,
            env=os.environ.copy(),
        )

    events = parse_json_events(result.stderr)
    stats = parse_stats_events(result.stderr)
    _require(result.returncode == 0, failures, f"sockopt fixture rc={result.returncode}")
    _require("sockopt-fixture-ok" in result.stdout, failures, "sockopt fixture marker missing")
    _require(len(stats) == 1, failures, "sockopt stats event missing")
    if stats:
        for key in ("ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail", "orphan_exit", "pending_mismatch", "lifecycle_map_update_fail"):
            _require(stats[0].get(key) == 0, failures, f"sockopt {key} is non-zero")

    for syscall in ("setsockopt", "getsockopt"):
        exits = [event for event in events if event.get("syscall") == syscall and event.get("event_type") == "exit"]
        _require(exits, failures, f"{syscall} exit event missing")
        _require(any(event.get("paired_enter") for event in exits), failures, f"{syscall} exit was not paired")
        _require(any(event.get("failed") and event.get("errno") == 9 for event in exits), failures, f"{syscall} EBADF failure missing")

    set_sections = _sections(events, "setsockopt", "enter", "in", 3)
    _require(any(section.get("user_len") == 4 and section.get("copied_len") == 4 and _section_bytes(section)[:4] == b"\x01\x00\x00\x00" for section in set_sections), failures, "setsockopt IN optval snapshot missing")

    get_value_sections = _sections(events, "getsockopt", "exit", "out", 3)
    _require(any(section.get("copied_len", 0) >= 4 and _section_bytes(section)[:4] == b"\x01\x00\x00\x00" for section in get_value_sections), failures, "getsockopt OUT optval snapshot missing")
    _require(any(section.get("copied_len") == 4 for section in _sections(events, "getsockopt", "exit", "out", 4)), failures, "getsockopt OUT optlen snapshot missing")
    _require(any(section.get("copied_len") == 4 for section in _sections(events, "getsockopt", "enter", "in", 4)), failures, "getsockopt IN optlen snapshot missing")

    text = " ".join(part for event in events for part in event.get("arg_text") or [])
    _require("SO_REUSEADDR" in text, failures, "sockopt option name missing")
    _require("[1]" in text, failures, "sockopt value was not decoded from snapshot")
    print(f"=> eBPF sockopt semantic events: {len(events)}")
    return failures
