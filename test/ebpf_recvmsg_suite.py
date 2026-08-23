#!/usr/bin/env python3
import base64
import os
import subprocess
from dataclasses import dataclass

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events, EVENT_FLAG_EXIT_FRAGMENT
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RECVMSG_FIXTURE_SOURCE = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_recvmsg_fixture.c"
)
RECVMSG_ZERO_STATS = (
    "ringbuf_reserve_fail",
    "ringbuf_copy_fail",
    "pending_update_fail",
    "orphan_exit",
    "pending_mismatch",
    "lifecycle_map_update_fail",
    "pending_stale",
)
RECVMSG_MARKERS = (b"rx-cmsg", b"rx-name")


@dataclass(frozen=True)
class SectionExpectation:
    kind: str
    direction: str
    arg_index: int
    minimum_len: int
    marker: bytes = None


def _section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def _recvmsg_events(events, event_type=None):
    return [
        event for event in events
        if event.get("syscall") == "recvmsg"
        and (event_type is None or event.get("event_type") == event_type)
    ]


def _has_section(events, event_type, expectation):
    for event in _recvmsg_events(events, event_type):
        if event.get("event_flags", 0) & EVENT_FLAG_EXIT_FRAGMENT:
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") != expectation.kind
                or section.get("direction") != expectation.direction
                or section.get("arg_index") != expectation.arg_index
                or section.get("probe_ret") != 0
                or section.get("user_len", 0) < expectation.minimum_len
                or section.get("copied_len", 0) < expectation.minimum_len
            ):
                continue
            data = _section_bytes(section)
            if len(data) < expectation.minimum_len:
                continue
            if expectation.marker is not None and expectation.marker not in data:
                continue
            return True
    return False


def _has_rights_cmsg(events):
    for event in _recvmsg_events(events, "exit"):
        if event.get("event_flags", 0) & EVENT_FLAG_EXIT_FRAGMENT:
            continue
        for section in event.get("payload_sections") or []:
            if section.get("kind") != "cmsg" or section.get("direction") != "out":
                continue
            data = _section_bytes(section)
            if len(data) < 20:
                continue
            cmsg_len = int.from_bytes(data[0:8], "little")
            level = int.from_bytes(data[8:12], "little", signed=True)
            cmsg_type = int.from_bytes(data[12:16], "little", signed=True)
            if cmsg_len >= 20 and level == 1 and cmsg_type == 1:
                return True
    return False


def _has_successful_exit(events):
    return sum(
        event.get("ret", -1) > 0
        and event.get("paired_enter") is True
        and not (event.get("event_flags", 0) & EVENT_FLAG_EXIT_FRAGMENT)
        for event in _recvmsg_events(events, "exit")
    ) >= 2


def _has_failed_exit_without_output(events):
    for event in _recvmsg_events(events, "exit"):
        if event.get("ret") != -9 or event.get("failed") is not True:
            continue
        if not any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        ):
            return True
    return False


def _has_sockaddr_text(events):
    text = " ".join(
        value
        for event in _recvmsg_events(events, "exit")
        for value in event.get("arg_text") or []
        if isinstance(value, str)
    )
    return "AF_INET" in text and "127.0.0.1" in text


def check_recvmsg_semantic(returncode, stdout, events, stats_events):
    failures = []
    require(returncode == 0, failures, f"recvmsg fixture rc={returncode}")
    require("recvmsg-fixture-ok" in stdout, failures, "recvmsg fixture marker missing")
    require(len(stats_events) == 1, failures, "recvmsg stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "recvmsg stats event is malformed")
        for key in RECVMSG_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"recvmsg {key} is non-zero")

    require(_has_successful_exit(events), failures, "recvmsg successful paired exits missing")
    require(_has_failed_exit_without_output(events), failures, "recvmsg failed OUT payload was fabricated")
    require(
        _has_section(events, "enter", SectionExpectation("struct", "in", 1, 56)),
        failures,
        "recvmsg IN msghdr missing",
    )
    require(
        _has_section(events, "enter", SectionExpectation("iovec", "in", 1, 16)),
        failures,
        "recvmsg IN iovec missing",
    )
    require(
        _has_section(events, "enter", SectionExpectation("cmsg", "in", 1, 16)),
        failures,
        "recvmsg IN cmsg missing",
    )
    require(_has_rights_cmsg(events), failures, "recvmsg OUT cmsg payload missing")
    require(
        _has_section(events, "exit", SectionExpectation("sockaddr", "out", 1, 16)),
        failures,
        "recvmsg OUT msg_name missing",
    )
    require(
        _has_section(events, "exit", SectionExpectation("struct", "out", 1, 56)),
        failures,
        "recvmsg OUT msghdr missing",
    )
    require(
        any(
            _has_section(
                events,
                "exit",
                SectionExpectation("bytes", "out", 120, 7, marker),
            )
            for marker in RECVMSG_MARKERS
        ),
        failures,
        "recvmsg OUT iovec bytes missing",
    )
    require(_has_sockaddr_text(events), failures, "recvmsg msg_name text missing")
    return failures


def run_recvmsg_semantic(wrapper, root):
    fixture = build_named_fixture(
        "strace-go-ebpf-recvmsg-fixture", (RECVMSG_FIXTURE_SOURCE,)
    )
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=socket,socketpair,bind,getsockname,sendmsg,recvmsg,close",
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
    failures = check_recvmsg_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
    )
    if not failures:
        print(f"=> eBPF recvmsg semantic events: {len(parse_json_events(result.stderr))}")
    return failures
