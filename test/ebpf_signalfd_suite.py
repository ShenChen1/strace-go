#!/usr/bin/env python3
import base64
import os
import subprocess
import tempfile

from ebpf_event_oracles import parse_json_events, parse_stats_events


SIGNALFD_STATE_ARG_INDEX = 0xFFFF
SIGNALFD_STATE_SIZE = 48
SIGNALFD_MASK_SIZE = 8
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_signalfd_fixture.c")


def build_fixture(project_root):
    output = os.path.join(tempfile.gettempdir(), "strace-go-ebpf-signalfd-fixture")
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-o", output, FIXTURE_SRC],
        cwd=project_root,
        check=True,
    )
    os.chmod(output, 0o755)
    return output


def section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except (TypeError, ValueError):
        return b""


def mask_from_event(event):
    for section in event.get("payload_sections") or []:
        if (
            section.get("kind") == "struct"
            and section.get("direction") == "in"
            and section.get("arg_index") == 1
            and section.get("user_len") == SIGNALFD_MASK_SIZE
            and section.get("copied_len") == SIGNALFD_MASK_SIZE
            and section.get("probe_ret") == 0
        ):
            data = section_bytes(section)
            if len(data) == SIGNALFD_MASK_SIZE:
                return int.from_bytes(data, "little")
    return None


def has_fd_state(event):
    for section in event.get("payload_sections") or []:
        if (
            section.get("kind") != "fd_state"
            or section.get("direction") != "out"
            or section.get("arg_index") != SIGNALFD_STATE_ARG_INDEX
            or section.get("user_len") != SIGNALFD_STATE_SIZE
            or section.get("copied_len") != SIGNALFD_STATE_SIZE
            or section.get("probe_ret") != 0
        ):
            continue
        data = section_bytes(section)
        if len(data) != SIGNALFD_STATE_SIZE:
            continue
        snapshot_fd = int.from_bytes(data[0:4], "little", signed=True)
        flags = int.from_bytes(data[4:8], "little")
        return snapshot_fd == event.get("ret") and (flags & 3) == 3
    return False


def successful_event(events, syscall):
    return next(
        (
            event
            for event in events
            if event.get("syscall") == syscall
            and event.get("event_type") == "exit"
            and event.get("ret", -1) >= 0
        ),
        None,
    )


def successful_exit_count(events, syscall):
    return sum(
        1
        for event in events
        if event.get("syscall") == syscall
        and event.get("event_type") == "exit"
        and event.get("ret", -1) >= 0
    )


def run_signalfd_semantic(wrapper, project_root):
    fixture = build_fixture(project_root)
    result = subprocess.run(
        [
            wrapper,
            "--event-format=json",
            "-y",
            "-e",
            "trace=signalfd,signalfd4,close,exit,exit_group",
            fixture,
        ],
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=30,
        env=os.environ.copy(),
    )
    events = parse_json_events(result.stderr)
    stats = parse_stats_events(result.stderr)
    failures = []
    if result.returncode != 0:
        failures.append(f"signalfd fixture rc={result.returncode}")
    if "signalfd-fixture-ok" not in result.stdout:
        failures.append("signalfd fixture stdout marker missing")
    if len(stats) != 1 or not stats[0].get("available"):
        failures.append("signalfd stats event missing")

    created = successful_event(events, "signalfd4")
    updated = successful_event(events, "signalfd")
    if created is None:
        failures.append("signalfd4 successful exit missing")
    else:
        if mask_from_event(created) != 1 << 11:
            failures.append("signalfd4 enter mask snapshot mismatch")
        if not has_fd_state(created):
            failures.append("signalfd4 FD_STATE snapshot missing")
        if "signalfd:[USR2]" not in created.get("return_text", ""):
            failures.append("signalfd4 return path missing initial mask")
    if updated is None:
        failures.append("signalfd successful update exit missing")
    else:
        if mask_from_event(updated) != (1 << 11 | 1 << 16):
            failures.append("signalfd enter mask update mismatch")
        if not has_fd_state(updated):
            failures.append("signalfd update FD_STATE snapshot missing")
        if "signalfd:[USR2 CHLD]" not in updated.get("return_text", ""):
            failures.append("signalfd update return path missing new mask")
    for syscall in ("signalfd", "signalfd4"):
        if successful_exit_count(events, syscall) != 1:
            failures.append(f"{syscall} emitted duplicate successful exit events")
    failed = [
        event
        for event in events
        if event.get("syscall") in ("signalfd", "signalfd4")
        and event.get("event_type") == "exit"
        and event.get("ret", 0) < 0
    ]
    if len(failed) < 2:
        failures.append("signalfd failure exits missing")
    if any(has_fd_state(event) for event in failed):
        failures.append("failed signalfd call emitted FD_STATE")
    if stats and any(stats[0].get(key, 0) != 0 for key in ("orphan_exit", "pending_mismatch")):
        failures.append("signalfd fixture reported pending/orphan errors")
    print(f"=> eBPF signalfd semantic events: {len(events)}")
    print(f"=> eBPF signalfd failure exits: {len(failed)}")
    return failures
