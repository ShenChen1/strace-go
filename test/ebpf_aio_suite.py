#!/usr/bin/env python3
import base64
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events
from ebpf_fixture_build import build_named_fixture


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AIO_FIXTURE_SOURCE = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_aio_fixture.c")
AIO_PAYLOAD_MARKERS = (b"ebpf-aio-first", b"ebpf-aio-second")
AIO_ZERO_STATS = (
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
    expectation,
):
    syscall, event_type, _, _, _, _, marker, _ = expectation
    for event in events:
        if event.get("syscall") != syscall or event.get("event_type") != event_type:
            continue
        for section in event.get("payload_sections") or []:
            if not _matches_section(section, expectation):
                continue
            if marker is not None and marker not in _section_bytes(section):
                continue
            return True
    return False


def _matches_section(section, expectation):
    _, _, kind, direction, arg_index, minimum, _, _ = expectation
    return (
        section.get("kind") == kind
        and section.get("direction") == direction
        and section.get("arg_index") == arg_index
        and section.get("probe_ret") == 0
        and section.get("user_len", 0) >= minimum
        and section.get("copied_len", 0) >= minimum
        and len(_section_bytes(section)) >= minimum
    )


def _has_paired_exit(events, syscall, successful=None):
    return any(
        event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("paired_enter") is True
        and (successful is None or (event.get("ret", -1) >= 0) is successful)
        for event in events
    )


def _failed_events_have_no_output(events):
    for event in events:
        if event.get("event_type") != "exit" or event.get("ret", 0) >= 0:
            continue
        if any(
            section.get("direction") == "out"
            for section in event.get("payload_sections") or []
        ):
            return False
    return True


def check_aio_semantic(returncode, stdout, events, stats_events, stderr=""):
    failures = []
    rc_msg = f"AIO fixture rc={returncode}"
    if stderr:
        rc_msg += f": stderr={stderr.strip()}"
    require(returncode == 0, failures, rc_msg)
    require("aio-fixture-ok" in stdout, failures, "AIO fixture marker missing")
    require(len(stats_events) == 1, failures, "AIO stats event missing")
    if stats_events:
        stats = stats_events[0]
        require(valid_stats_event(stats), failures, "AIO stats event is malformed")
        for key in AIO_ZERO_STATS:
            require(stats.get(key) == 0, failures, f"AIO {key} is non-zero")

    for syscall in ("io_setup", "io_submit", "io_getevents", "io_pgetevents"):
        require(
            _has_paired_exit(events, syscall, True),
            failures,
            f"{syscall} successful paired exit missing",
        )
    require(
        _has_paired_exit(events, "io_cancel", False),
        failures,
        "io_cancel failed paired exit missing",
    )
    for syscall in ("io_getevents", "io_pgetevents"):
        require(
            any(
                event.get("syscall") == syscall
                and event.get("event_type") == "exit"
                and event.get("ret") == -14
                and event.get("paired_enter") is True
                for event in events
            ),
            failures,
            f"{syscall} EFAULT failure missing",
        )

    payload_checks = (
        ("io_setup", "exit", "struct", "out", 1, 8, None, "io_setup context"),
        ("io_submit", "exit", "struct", "in", 2, 8, None, "io_submit pointer array"),
        ("io_submit", "exit", "struct", "in", 20, 64, None, "io_submit iocb"),
        (
            "io_submit", "exit", "bytes", "in", 60, 1,
            AIO_PAYLOAD_MARKERS[0], "io_submit first buffer",
        ),
        (
            "io_submit", "exit", "bytes", "in", 60, 1,
            AIO_PAYLOAD_MARKERS[1], "io_submit second buffer",
        ),
        ("io_getevents", "exit", "struct", "in", 4, 16, None, "io_getevents timeout"),
        ("io_getevents", "exit", "struct", "out", 3, 32, None, "io_getevents event"),
        ("io_pgetevents", "exit", "struct", "in", 4, 16, None, "io_pgetevents timeout"),
        ("io_pgetevents", "exit", "struct", "in", 5, 16, None, "io_pgetevents wrapper"),
        ("io_pgetevents", "exit", "bytes", "in", 5, 8, None, "io_pgetevents sigmask"),
        ("io_pgetevents", "exit", "struct", "out", 3, 32, None, "io_pgetevents event"),
        ("io_cancel", "exit", "struct", "in", 1, 64, None, "io_cancel iocb"),
    )
    for expectation in payload_checks:
        require(
            _has_payload(events, expectation),
            failures,
            f"{expectation[-1]} snapshot missing",
        )
    require(_failed_events_have_no_output(events), failures, "AIO failure fabricated OUT payload")
    return failures


def run_aio_semantic(wrapper, root):
    fixture = build_named_fixture("strace-go-ebpf-aio-fixture", (AIO_FIXTURE_SOURCE,))
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-e",
            "trace=io_setup,io_submit,io_getevents,io_pgetevents,io_cancel,io_destroy,close",
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
    failures = check_aio_semantic(
        result.returncode,
        result.stdout,
        parse_json_events(result.stderr),
        parse_stats_events(result.stderr),
        result.stderr,
    )
    if not failures:
        print(f"=> eBPF AIO semantic events: {len(parse_json_events(result.stderr))}")
    return failures
