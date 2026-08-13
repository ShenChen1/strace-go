#!/usr/bin/env python3
import os

from ebpf_event_oracles import (
    EVENT_FLAG_TRUNCATED,
    StructPayloadSpec,
    has_bytes_payload_section,
    has_dup_fd_state_sections,
    has_fd_array_fd_state_sections,
    has_fcntl_fd_state_for_command,
    has_exec_payload_sections,
    has_fd_state_section,
    has_open_family_path_and_fd_state,
    has_openat2_path_how_and_fd_state,
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
        "lifecycle_map_update_fail",
        "pending_stale",
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
    require(stats.get("lifecycle_map_update_fail", 0) == 0, failures, "normal semantic fixture reported lifecycle map update failure")
    require(stats.get("pending_stale", 0) == 0, failures, "normal semantic fixture left stale pending syscall state")


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
    require("openat2" in names, failures, "openat2 event missing")


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


def check_fd_state_payloads(context, failures):
    require(
        has_open_family_path_and_fd_state(context.main.events),
        failures,
        "open-family path and FD state were not combined in one exit event",
    )
    require(
        has_openat2_path_how_and_fd_state(context.main.events),
        failures,
        "openat2 path, how, and FD state were not combined in one exit event",
    )
    require(has_fd_state_section(context.main.events), failures, "open-family FD state payload section missing")
    require(has_dup_fd_state_sections(context.main.events), failures, "dup-family FD state payload sections missing")
    require(has_fd_array_fd_state_sections(context.main.events), failures, "pipe/socketpair FD state payload sections missing")
    events = context.fcntl.events
    require(context.fcntl.result.returncode == 0, failures, f"fcntl fixture rc={context.fcntl.result.returncode}")
    require(has_fcntl_fd_state_for_command(events, 0), failures, "F_DUPFD FD state payload section missing")
    require(has_fcntl_fd_state_for_command(events, 1030), failures, "F_DUPFD_CLOEXEC FD state payload section missing")
    require(not has_fcntl_fd_state_for_command(events, 3), failures, "F_GETFL was incorrectly encoded as FD state")


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


def check_attach_thread(context, failures):
    capture = context.attach_thread
    require(capture.target_rc == 0, failures, f"non-leader attach fixture rc={capture.target_rc}")
    require("attach-thread-fixture-ok" in capture.target_stdout, failures, "non-leader attach fixture stdout marker missing")
    require(capture.result.returncode == 0, failures, f"non-leader attach tracer rc={capture.result.returncode}")
    require(capture.attach_tid > 0, failures, "non-leader attach TID missing")
    syscalls = [event for event in capture.events if event.get("syscall") == "getpid"]
    require(syscalls, failures, "non-leader attach getpid events missing")
    require(any(event.get("event_type") == "enter" for event in syscalls), failures, "non-leader attach enter event missing")
    require(any(event.get("event_type") == "exit" for event in syscalls), failures, "non-leader attach exit event missing")
    require(
        all(event.get("tid") == capture.attach_tid and event.get("pid") != capture.attach_tid for event in syscalls),
        failures,
        "non-leader attach events did not retain exact TID identity",
    )
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "non-leader attach stats event missing")
    stats = capture.stats_events[0] if capture.stats_events else {}
    for key in ("orphan_exit", "pending_mismatch", "pending_stale"):
        require(stats.get(key, 1) == 0, failures, f"non-leader attach reported {key}")


def matching_sections(events, syscall, event_type):
    sections = []
    for event in events:
        if event.get("syscall") == syscall and event.get("event_type") == event_type:
            sections.extend(event.get("payload_sections") or [])
    return sections


def has_copied_section(sections, kind, direction, arg_index, minimum_copied):
    return any(
        section.get("kind") == kind
        and section.get("direction") == direction
        and section.get("arg_index") == arg_index
        and section.get("copied_len", 0) >= minimum_copied
        for section in sections
    )


def check_mount_query(context, failures):
    capture = context.mount_query
    require(capture.result.returncode == 0, failures, f"mount-query fixture rc={capture.result.returncode}")
    require("mount-query-fixture-ok" in capture.result.stdout, failures, "mount-query fixture stdout marker missing")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "mount-query stats event missing")
    error_counters = (
        "ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail",
        "orphan_exit", "pending_mismatch", "lifecycle_map_update_fail",
    )
    clean_stats = capture.stats_events and all(
        capture.stats_events[0].get(key, 1) == 0 for key in error_counters
    )
    require(clean_stats, failures, "mount-query fixture reported runtime event errors")

    list_enter = matching_sections(capture.events, "listmount", "enter")
    list_exit = matching_sections(capture.events, "listmount", "exit")
    stat_enter = matching_sections(capture.events, "statmount", "enter")
    stat_exit = matching_sections(capture.events, "statmount", "exit")
    require(has_copied_section(list_enter, "struct", "in", 0, 32), failures, "listmount request snapshot missing")
    require(has_copied_section(list_exit, "bytes", "out", 1, 8), failures, "listmount mount ID output snapshot missing")
    require(has_copied_section(stat_enter, "struct", "in", 0, 32), failures, "statmount request snapshot missing")
    require(has_copied_section(stat_exit, "struct", "out", 1, 512), failures, "statmount fixed output snapshot missing")
    require(has_copied_section(stat_exit, "bytes", "out", 1, 1), failures, "statmount string output snapshot missing")
    require(any(event.get("syscall") == "listmount" and event.get("event_type") == "exit" and event.get("paired_enter") for event in capture.events), failures, "listmount exit was not paired")
    require(any(event.get("syscall") == "statmount" and event.get("event_type") == "exit" and event.get("paired_enter") for event in capture.events), failures, "statmount exit was not paired")
    arg_text = " ".join(
        part
        for event in capture.exit_events
        for part in (event.get("arg_text") or [])
    )
    require("LSMT_ROOT" in arg_text, failures, "listmount root ID text missing")
    require("STATMOUNT_SB_BASIC" in arg_text, failures, "statmount mask text missing")
    require("fs_type=" in arg_text, failures, "statmount filesystem type text missing")


def has_text_section(sections, arg_index, text):
    return any(
        section.get("kind") == "string"
        and section.get("direction") == "in"
        and section.get("arg_index") == arg_index
        and text in payload_section_text(section)
        for section in sections
    )


def check_mount_path_capture(capture, failures, label, snapshot_event_type):
    require(capture.result.returncode == 0, failures, f"{label} fixture rc={capture.result.returncode}")
    require("mount-path-fixture-ok" in capture.result.stdout, failures, f"{label} fixture stdout marker missing")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, f"{label} stats event missing")
    error_counters = (
        "ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail",
        "orphan_exit", "pending_mismatch", "lifecycle_map_update_fail",
    )
    clean_stats = capture.stats_events and all(
        capture.stats_events[0].get(key, 1) == 0 for key in error_counters
    )
    require(clean_stats, failures, f"{label} reported runtime event errors")

    open_sections = matching_sections(capture.events, "open_tree", snapshot_event_type)
    move_sections = matching_sections(capture.events, "move_mount", snapshot_event_type)
    require(has_text_section(open_sections, 1, "/dev/full"), failures, f"{label} open_tree path snapshot missing")
    require(has_text_section(move_sections, 1, "/dev/full"), failures, f"{label} move_mount source snapshot missing")
    require(has_text_section(move_sections, 3, "/tmp/strace-go-ebpf-move-target"), failures, f"{label} move_mount target snapshot missing")
    for syscall in ("open_tree", "move_mount"):
        paired = any(
            event.get("syscall") == syscall
            and event.get("event_type") == "exit"
            and event.get("paired_enter")
            for event in capture.events
        )
        require(paired, failures, f"{label} {syscall} exit was not paired")


def check_mount_path(context, failures):
    check_mount_path_capture(context.mount_path, failures, "mount-path", "enter")
    check_mount_path_capture(
        context.mount_path_filtered, failures, "mount-path filter", "exit"
    )
    arg_text = " ".join(
        part
        for event in context.mount_path.exit_events
        for part in (event.get("arg_text") or [])
    )
    require("OPEN_TREE_CLONE" in arg_text, failures, "open_tree symbolic flags missing")
    require("MOVE_MOUNT_BENEATH" in arg_text, failures, "move_mount symbolic flags missing")


def check_dirent(context, failures):
    capture = context.dirent
    require(capture.result.returncode == 0, failures, f"dirent fixture rc={capture.result.returncode}")
    require("dirent-fixture-ok" in capture.result.stdout, failures, "dirent fixture stdout marker missing")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "dirent stats event missing")
    error_counters = (
        "ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail",
        "orphan_exit", "pending_mismatch", "lifecycle_map_update_fail",
    )
    clean_stats = capture.stats_events and all(
        capture.stats_events[0].get(key, 1) == 0 for key in error_counters
    )
    require(clean_stats, failures, "dirent fixture reported runtime event errors")

    for syscall in ("getdents", "getdents64"):
        successful = [
            event for event in capture.exit_events
            if event.get("syscall") == syscall and event.get("ret", 0) > 0
        ]
        require(successful, failures, f"{syscall} successful exit missing")
        require(any(event.get("paired_enter") for event in successful), failures, f"{syscall} exit was not paired")
        sections = [
            section
            for event in successful
            for section in (event.get("payload_sections") or [])
        ]
        require(has_copied_section(sections, "bytes", "out", 1, 1), failures, f"{syscall} OUT bytes snapshot missing")
        failed = any(
            event.get("syscall") == syscall and event.get("failed")
            and event.get("errno") == 9
            for event in capture.exit_events
        )
        require(failed, failures, f"{syscall} EBADF failure event missing")


def check_mmsg(context, failures):
    capture = context.mmsg
    require(capture.result.returncode == 0, failures, f"mmsg fixture rc={capture.result.returncode}")
    require("mmsg-fixture-ok" in capture.result.stdout, failures, "mmsg fixture stdout marker missing")
    require(len(capture.stats_events) == 1 and valid_stats_event(capture.stats_events[0]), failures, "mmsg stats event missing")
    error_counters = (
        "ringbuf_reserve_fail", "ringbuf_copy_fail", "pending_update_fail",
        "orphan_exit", "pending_mismatch", "lifecycle_map_update_fail",
    )
    clean_stats = capture.stats_events and all(
        capture.stats_events[0].get(key, 1) == 0 for key in error_counters
    )
    require(clean_stats, failures, "mmsg fixture reported runtime event errors")
    for syscall in ("sendmmsg", "recvmmsg"):
        successful = [
            event for event in capture.exit_events
            if event.get("syscall") == syscall and event.get("ret", 0) > 0
        ]
        require(successful, failures, f"{syscall} successful exit missing")
        require(any(event.get("paired_enter") for event in successful), failures, f"{syscall} exit was not paired")
        sections = [
            section
            for event in capture.events
            if event.get("syscall") == syscall
            for section in (event.get("payload_sections") or [])
        ]
        struct_sections = [
            section for section in sections
            if section.get("kind") == "struct" and section.get("arg_index") == 1
        ]
        require(any(section.get("user_len") == 320 and section.get("copied_len") == 256 for section in struct_sections), failures, f"{syscall} four-slot mmsghdr bound missing")
        require(any(event.get("event_flags", 0) & EVENT_FLAG_TRUNCATED for event in capture.events if event.get("syscall") == syscall), failures, f"{syscall} mmsghdr truncation flag missing")
        for arg_index in (1, 151, 181, 211):
            require(any(section.get("kind") == "iovec" and section.get("arg_index") == arg_index for section in sections), failures, f"{syscall} iovec slot arg {arg_index} missing")
        bytes_direction = "in" if syscall == "sendmmsg" else "out"
        bytes_arg_indices = (120, 160, 180, 200)
        for arg_index in bytes_arg_indices:
            require(
                any(
                    section.get("kind") == "bytes"
                    and section.get("direction") == bytes_direction
                    and section.get("arg_index") == arg_index
                    and section.get("copied_len", 0) > 0
                    for section in sections
                ),
                failures,
                f"{syscall} {bytes_direction} buffer arg {arg_index} missing",
            )


def check_semantic_context(context, failures):
    check_main_capture(context, failures)
    check_syscall_presence(context, failures)
    check_path_and_bytes_payloads(context, failures)
    check_fd_state_payloads(context, failures)
    check_out_struct_payloads(context, failures)
    check_in_struct_payloads(context, failures)
    check_pairing_and_write_payloads(context, failures)
    check_lifecycle(context, failures)
    check_thread(context, failures)
    check_attach(context, failures)
    check_attach_thread(context, failures)
    check_mount_query(context, failures)
    check_mount_path(context, failures)
    check_dirent(context, failures)
    check_mmsg(context, failures)
