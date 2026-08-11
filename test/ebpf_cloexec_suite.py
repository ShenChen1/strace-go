#!/usr/bin/env python3
import os
import subprocess
import tempfile

from ebpf_event_oracles import (
    has_fd_state_for_syscall,
    parse_json_events,
    parse_lifecycle_events,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_cloexec_exec_fixture.c")
STRACE_WRAPPER = os.path.join(SCRIPT_DIR, "strace-sudo.sh")
FIXTURE_PATH = "/tmp/strace-go-ebpf-cloexec-state"
CLOSE_RANGE_UNSHARE = 1 << 1
CLOSE_RANGE_CLOEXEC = 1 << 2


def build_fixture():
    output = os.path.join(
        tempfile.gettempdir(), f"strace-go-ebpf-cloexec-fixture-{os.getuid()}"
    )
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-o", output, FIXTURE_SRC],
        cwd=PROJECT_ROOT,
        check=True,
    )
    os.chmod(output, 0o755)
    return output


def has_stale_cloexec_read(events):
    return any(
        event.get("syscall") == "read"
        and event.get("event_type") == "exit"
        and event.get("ret") == -9
        for event in events
    )


def has_successful_exit(events, syscall_name):
    return any(
        event.get("syscall") == syscall_name
        and event.get("event_type") == "exit"
        and event.get("ret", -1) >= 0
        for event in events
    )


def run_cloexec_semantic():
    fixture = build_fixture()
    command = [
        STRACE_WRAPPER,
        "--event-format=json",
        "-f",
        "-e",
        "trace=open,openat,read,close,dup3,fcntl,pipe2,eventfd,eventfd2,epoll_create,epoll_create1,timerfd_create,inotify_init,inotify_init1,close_range,execve,exit,exit_group",
        fixture,
    ]
    result = subprocess.run(
        command[:3] + ["-P", FIXTURE_PATH] + command[3:],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    presence_result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    events = parse_json_events(result.stderr)
    presence_events = parse_json_events(presence_result.stderr)
    lifecycle = parse_lifecycle_events(result.stderr)
    failures = []
    if result.returncode != 0 or presence_result.returncode != 0:
        failures.append(
            f"cloexec fixture rc={result.returncode}/{presence_result.returncode}"
        )
    if "cloexec-child-ebadf" not in result.stdout:
        failures.append("cloexec child did not observe EBADF after exec")
    for syscall_name in (
        "open",
        "dup3",
        "pipe2",
        "eventfd",
        "eventfd2",
        "epoll_create",
        "epoll_create1",
        "timerfd_create",
        "inotify_init",
        "inotify_init1",
    ):
        if not has_successful_exit(presence_events, syscall_name):
            failures.append(f"cloexec {syscall_name} exit event missing")
    for syscall_name in (
        "eventfd",
        "eventfd2",
        "epoll_create",
        "epoll_create1",
        "timerfd_create",
        "inotify_init",
        "inotify_init1",
    ):
        if not has_fd_state_for_syscall(presence_events, syscall_name):
            failures.append(f"cloexec {syscall_name} FD_STATE snapshot missing")
    close_range_events = [
        event
        for event in presence_events
        if event.get("syscall") == "close_range" and event.get("event_type") == "exit"
    ]
    if not any(
        event.get("ret") == 0
        and len(event.get("args") or []) >= 3
        and (event.get("args") or [0, 0, 0])[2] == 0
        for event in close_range_events
    ):
        failures.append("cloexec normal close_range exit event missing")
    if not any(
        event.get("ret") == 0
        and len(event.get("args") or []) >= 3
        and (event.get("args") or [0, 0, 0])[2] & CLOSE_RANGE_CLOEXEC
        for event in close_range_events
    ):
        failures.append("cloexec CLOSE_RANGE_CLOEXEC exit event missing")
    if not any(
        event.get("ret") == 0
        and len(event.get("args") or []) >= 3
        and (event.get("args") or [0, 0, 0])[2]
        == CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC
        for event in close_range_events
    ):
        failures.append("cloexec combined close_range exit event missing")
    if not any(event.get("ret", 0) < 0 for event in close_range_events):
        failures.append("cloexec failed close_range exit event missing")
    if not any(
        event.get("syscall") == "fcntl"
        and event.get("event_type") == "exit"
        and event.get("ret") == 0
        and len(event.get("args") or []) >= 2
        and (event.get("args") or [0, 0])[1] == 2
        for event in presence_events
    ):
        failures.append("cloexec F_SETFD exit event missing")
    if not any(event.get("action") == "exec" for event in lifecycle):
        failures.append("cloexec exec lifecycle event missing")
    if has_stale_cloexec_read(events):
        failures.append("CLOEXEC FD path state survived exec and matched EBADF read")
    return failures
