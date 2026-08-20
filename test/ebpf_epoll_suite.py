#!/usr/bin/env python3
import os
import subprocess

from ebpf_check_support import require, valid_stats_event
from ebpf_event_oracles import parse_json_events, parse_stats_events, payload_section_text
from ebpf_fixture_build import build_named_fixture


EPOLL_FIFO_PATH = "/tmp/strace-go-ebpf-epoll-fifo"
NESTED_FD_PATH_ARG_INDEX = 0xFFFD
EPOLL_FIXTURE_SOURCE = os.path.join(
    os.path.dirname(__file__), "fixtures", "ebpf_epoll_fixture.c"
)


def _run_fixture(wrapper, fixture):
    return subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-y",
            "-e",
            "trace=epoll_create1,epoll_ctl,epoll_wait,write,close,unlink",
            fixture,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )


def _has_nested_epoll_path(events):
    for event in events:
        if (
            event.get("syscall") != "epoll_wait"
            or event.get("event_type") != "exit"
            or event.get("ret") != 1
            or not event.get("paired_enter")
        ):
            continue
        for section in event.get("payload_sections") or []:
            if (
                section.get("kind") == "fd_path"
                and section.get("direction") == "in"
                and section.get("arg_index") == NESTED_FD_PATH_ARG_INDEX
                and section.get("probe_ret") == 0
                and section.get("copied_len", 0) > 0
                and EPOLL_FIFO_PATH in payload_section_text(section)
            ):
                return True
    return False


def run_epoll_semantic(wrapper):
    fixture = build_named_fixture(
        "strace-go-ebpf-epoll-fixture", (EPOLL_FIXTURE_SOURCE,)
    )
    result = _run_fixture(wrapper, fixture)
    events = parse_json_events(result.stderr)
    stats_events = parse_stats_events(result.stderr)
    failures = []
    require(result.returncode == 0, failures, f"epoll fixture rc={result.returncode}")
    require("epoll-fixture-ok" in result.stdout, failures, "epoll fixture marker missing")
    require(len(stats_events) == 1 and valid_stats_event(stats_events[0]), failures, "epoll stats event missing")
    require(_has_nested_epoll_path(events), failures, "epoll_wait nested FD path snapshot missing")
    if stats_events:
        stats = stats_events[0]
        for key in ("ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail", "orphan_exit", "pending_mismatch", "pending_stale"):
            require(stats.get(key, 1) == 0, failures, f"epoll fixture reported {key}")
    return failures
