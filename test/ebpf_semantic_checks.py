#!/usr/bin/env python3
import os

from ebpf_event_oracles import (
    StructPayloadSpec,
    has_bytes_payload_section,
    has_exec_payload_sections,
    has_gettimeofday_payload_sections,
    has_large_write_truncation,
    has_openat_path_section,
    has_path_section,
    has_sendmsg_cmsg_section,
    has_stat_payload_section,
    has_struct_payload_section,
    has_struct_payload_section_with_direction,
    payload_section_text,
)


def require(condition, failures, message):
    if not condition:
        failures.append(message)


def valid_stats_event(event):
    keys = (
        "ringbuf_reserve_fail",
        "ringbuf_copy_fail",
        "payload_truncated_events",
        "pending_update_fail",
        "orphan_exit",
        "pending_mismatch",
    )
    return event.get("available") is True and all(
        isinstance(event.get(key), int) and event.get(key) >= 0 for key in keys
    )


def check_semantic_stats(stats_events, failures):
    require(len(stats_events) == 1, failures, "stats JSON event missing")
    require(
        all(valid_stats_event(event) for event in stats_events),
        failures,
        "stats JSON event has invalid counters",
    )
    stats = stats_events[0] if stats_events else {}
    require(stats.get("payload_truncated_events", 0) > 0, failures, "truncated payload stats counter missing")
    require(stats.get("pending_mismatch", 0) == 0, failures, "normal semantic fixture reported pending syscall mismatch")
    require(stats.get("pending_update_fail", 0) == 0, failures, "normal semantic fixture reported pending map update failure")
    require(stats.get("orphan_exit", 0) == 0, failures, "normal semantic fixture reported orphan exit")


def check_main_capture(context, failures):
    capture = context.main
    require(capture.result.returncode == 0, failures, f"semantic fixture rc={capture.result.returncode}")
    require("ebpf-fixture-write" in capture.result.stdout, failures, "fixture stdout marker missing")
    require(capture.events, failures, "no JSON syscall events decoded")
    require(capture.enter_events, failures, "no syscall enter JSON events decoded")
    require(capture.exit_events, failures, "no syscall exit JSON events decoded")
    check_semantic_stats(capture.stats_events, failures)


def check_syscall_presence(context, failures):
    names = {event.get("syscall") for event in context.main.events}
    expected = {
        "write", "pwrite64", "pread64", "read", "close", "stat", "lstat",
        "fstat", "newfstatat", "statfs", "fstatfs", "getcwd", "readlink",
        "readlinkat", "pipe", "pipe2", "socketpair", "uname", "sysinfo",
        "getrlimit", "setrlimit", "prlimit64", "arch_prctl", "get_robust_list",
        "sendfile", "copy_file_range", "getitimer", "setitimer", "clock_settime",
        "settimeofday", "adjtimex", "nanosleep", "clock_nanosleep", "futex",
        "futex_wait", "futex_waitv", "futex_requeue", "sendmsg", "clock_gettime",
        "gettimeofday", "execve",
    }
    for name in sorted(expected):
        require(name in names, failures, f"{name} event missing")
    require("openat" in names or "open" in names, failures, "open/openat event missing")


def check_path_and_bytes_payloads(context, failures):
    events = context.main.events
    path_specs = (
        ("statfs", 0, "/proc/self"),
        ("stat", 0, "/proc/self"),
        ("lstat", 0, "/proc/self"),
        ("newfstatat", 1, "/proc/self"),
        ("readlink", 0, "/tmp/strace-go-ebpf-readlink-"),
        ("readlinkat", 1, "/tmp/strace-go-ebpf-readlink-"),
    )
    require(has_openat_path_section(events, "/tmp/strace-go-ebpf-missing-file"), failures, "openat path payload section missing")
    for syscall, arg_index, text in path_specs:
        require(has_path_section(events, syscall, arg_index, text), failures, f"{syscall} path payload section missing")
    byte_specs = (
        ("getcwd", 0, "strace-go"),
        ("readlink", 1, "/proc/self"),
        ("readlinkat", 2, "/proc/self"),
    )
    for syscall, arg_index, text in byte_specs:
        require(has_bytes_payload_section(events, syscall, arg_index, text), failures, f"{syscall} OUT bytes payload section missing")
    require(has_exec_payload_sections(events), failures, "execve argv/envp and filename payload sections missing")
    require(has_gettimeofday_payload_sections(events), failures, "gettimeofday OUT timeval/timezone payload sections missing")


def check_out_struct_payloads(context, failures):
    events = context.main.events
    specs = (
        ("clock_gettime", 1, 16), ("fstat", 1, 144), ("statfs", 1, 120),
        ("fstatfs", 1, 120), ("pipe", 0, 8), ("pipe2", 0, 8),
        ("socketpair", 3, 8), ("uname", 0, 390), ("sysinfo", 0, 112),
        ("getrlimit", 1, 16), ("prlimit64", 3, 16), ("arch_prctl", 1, 8),
        ("get_robust_list", 1, 8), ("get_robust_list", 2, 8),
        ("sendfile", 2, 8), ("getitimer", 1, 32), ("setitimer", 2, 32),
        ("adjtimex", 0, 208),
    )
    for syscall, arg_index, size in specs:
        require(has_struct_payload_section(events, syscall, arg_index, size), failures, f"{syscall} OUT struct payload section missing")
    for syscall, arg_index in (("stat", 1), ("lstat", 1), ("newfstatat", 2)):
        require(has_stat_payload_section(events, syscall, arg_index), failures, f"{syscall} OUT stat payload section missing")


def check_in_struct_payloads(context, failures):
    events = context.main.events
    specs = (
        StructPayloadSpec("setrlimit", "enter", "in", 1, 16),
        StructPayloadSpec("prlimit64", "enter", "in", 2, 16),
        StructPayloadSpec("sendfile", "enter", "in", 2, 8),
        StructPayloadSpec("copy_file_range", "enter", "in", 1, 8),
        StructPayloadSpec("copy_file_range", "enter", "in", 3, 8),
        StructPayloadSpec("setitimer", "enter", "in", 1, 32),
        StructPayloadSpec("clock_settime", "enter", "in", 1, 16),
        StructPayloadSpec("settimeofday", "enter", "in", 0, 16),
        StructPayloadSpec("settimeofday", "enter", "in", 1, 8),
        StructPayloadSpec("nanosleep", "enter", "in", 0, 16),
        StructPayloadSpec("clock_nanosleep", "enter", "in", 2, 16),
        StructPayloadSpec("futex", "enter", "in", 3, 16),
        StructPayloadSpec("futex_wait", "enter", "in", 4, 16),
        StructPayloadSpec("futex_waitv", "enter", "in", 0, 48),
        StructPayloadSpec("futex_waitv", "enter", "in", 3, 16),
        StructPayloadSpec("futex_requeue", "enter", "in", 0, 48),
    )
    for spec in specs:
        require(has_struct_payload_section_with_direction(events, spec), failures, f"{spec.syscall} IN struct payload section missing")
    require(has_sendmsg_cmsg_section(events), failures, "sendmsg IN cmsg payload section missing")


def check_pairing_and_write_payloads(context, failures):
    capture = context.main
    for syscall in ("write", "read"):
        require(any(event.get("syscall") == syscall for event in capture.enter_events), failures, f"{syscall} enter event missing")
        require(any(event.get("syscall") == syscall for event in capture.exit_events), failures, f"{syscall} exit event missing")
    for syscall in ("write", "read", "pwrite64", "pread64"):
        require(any(event.get("syscall") == syscall and event.get("paired_enter") for event in capture.exit_events), failures, f"{syscall} exit was not paired with enter")
    require(any(event.get("syscall") in ("exit", "exit_group") and event.get("event_type") == "exit" and event.get("paired_enter") for event in capture.exit_events), failures, "exit/exit_group direct event was not paired")
    require(any(event.get("failed") and event.get("errno") == 2 for event in capture.events), failures, "ENOENT failed-open event missing")
    require(any(event.get("syscall") == "write" and "ebpf-fixture-write" in " ".join(event.get("arg_text") or []) for event in capture.events), failures, "write payload text missing from arg_text")
    require(has_large_write_truncation(capture.events), failures, "large write payload truncation metadata missing")
    for syscall, direction, text in (("write", "in", "ebpf-fixture-write"), ("pwrite64", "in", "ebpf-fixture-pwrite"), ("pread64", "out", "ebpf-fixture-pwrite")):
        found = any(event.get("syscall") == syscall and any(section.get("kind") == "bytes" and section.get("direction") == direction and section.get("arg_index") == 1 and text in payload_section_text(section) for section in event.get("payload_sections") or []) for event in capture.events)
        require(found, failures, f"{syscall} payload section missing")


def check_lifecycle(context, failures):
    events = context.main.lifecycle_events
    actions = {event.get("action") for event in events}
    require(len({event.get("pid") for event in context.main.events}) >= 2, failures, "forked child pid events missing")
    for action in ("fork", "exec"):
        require(action in actions, failures, f"{action} lifecycle event missing")
    require("exit" in actions or "free" in actions, failures, "exit/free lifecycle event missing")
    require(any(event.get("action") == "fork" and event.get("task_tid") == event.get("arg1") and event.get("parent_tid") == event.get("arg0") and event.get("alive") for event in events), failures, "fork lifecycle task state missing")
    require(any(event.get("action") == "exec" and event.get("execed") and event.get("alive") for event in events), failures, "exec lifecycle task state missing")
    require(any(event.get("action") == "exec" and os.path.basename(event.get("filename") or "") == "true" for event in events), failures, "exec lifecycle filename missing")
    require(any(event.get("action") in ("exit", "free") and event.get("alive") is False for event in events), failures, "exit/free task state stayed alive")


def check_thread(context, failures):
    capture = context.thread
    syscalls = [event for event in capture.events if event.get("syscall") == "getpid" and event.get("tid") != event.get("pid")]
    forks = [event for event in capture.lifecycle_events if event.get("action") == "fork"]
    lifecycle = [event for event in capture.lifecycle_events if event.get("action") in ("exit", "free") and event.get("tid") != event.get("pid")]
    require(capture.result.returncode == 0, failures, f"thread fixture rc={capture.result.returncode}")
    require("thread-fixture-ok" in capture.result.stdout, failures, "thread fixture stdout marker missing")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "thread stats event missing")
    require(syscalls, failures, "non-leader thread getpid events missing")
    require(any(event.get("event_type") == "exit" and event.get("paired_enter") for event in syscalls), failures, "thread getpid exit not paired")
    require(lifecycle, failures, "non-leader thread lifecycle identity missing")
    require(any(event.get("task_tid") == event.get("arg1") and not event.get("task_tgid") for event in forks), failures, "thread fork guessed child TGID")
    require(any(event.get("task_tgid") == event.get("pid") for event in lifecycle), failures, "thread lifecycle did not resolve TGID")
    text = context.thread_text.stderr
    require(context.thread_text.returncode == 0, failures, f"thread text rc={context.thread_text.returncode}")
    require("thread-fixture-ok" in context.thread_text.stdout, failures, "thread text stdout marker missing")
    require("read(" in text and "<unfinished ...>" in text, failures, "thread unfinished output missing")
    require("<... read resumed>)" in text, failures, "thread resumed output missing")


def check_attach(context, failures):
    capture = context.attach
    require(capture.target_rc == 0, failures, f"attach fixture rc={capture.target_rc}")
    require("attach-fixture-ok" in capture.target_stdout, failures, "attach fixture stdout marker missing")
    require(capture.result.returncode == 0, failures, f"attach tracer rc={capture.result.returncode}")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "attach stats event missing")
    require(capture.stats_events and capture.stats_events[0].get("orphan_exit", 0) > 0, failures, "attach orphan_exit diagnostic missing")


def check_semantic_context(context, failures):
    check_main_capture(context, failures)
    check_syscall_presence(context, failures)
    check_path_and_bytes_payloads(context, failures)
    check_out_struct_payloads(context, failures)
    check_in_struct_payloads(context, failures)
    check_pairing_and_write_payloads(context, failures)
    check_lifecycle(context, failures)
    check_thread(context, failures)
    check_attach(context, failures)
