#!/usr/bin/env python3
import os
import glob
import subprocess
import sys
import argparse
import multiprocessing
import json
import tempfile
import time
import base64
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

from upstream_suites import (
    MORE_EXPECTED_FAILURES,
    MORE_TESTS,
    SMOKE_TESTS,
    UPSTREAM_REFERENCE_EXPECTED_FAILURES,
    UPSTREAM_REFERENCE_TESTS,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

TESTS_DIR = os.path.join(PROJECT_ROOT, "strace-upstream", "tests")
UPSTREAM_DIR = os.path.join(PROJECT_ROOT, "strace-upstream")
STRACE_WRAPPER = os.path.join(SCRIPT_DIR, "strace-sudo.sh")
STRACE_GO_BIN = os.path.join(PROJECT_ROOT, "strace-go")
FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_semantic_fixture.c")
THREAD_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_thread_fixture.c")
ATTACH_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_attach_fixture.c")
EVENT_FLAG_TRUNCATED = 4

def parse_args():
    parser = argparse.ArgumentParser(description="Unified test framework for strace-go")
    parser.add_argument("--suite", choices=["small", "more", "all", "upstream-reference", "ebpf-semantic", "ebpf-perf"], default="small",
                        help="Which test suite to run")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit the number of tests to run (0 for unlimited)")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Number of parallel workers (default 1)")
    parser.add_argument("--filter", type=str, default="", help="Filter specific test by exact name")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip building upstream strace tests")
    return parser.parse_args()

def setup_env():
    os.environ["STRACE"] = STRACE_WRAPPER
    os.environ["SIZEOF_LONG"] = "8"
    os.environ["STRACE_ARCH"] = "x86_64"
    os.environ["STRACE_NATIVE_ARCH"] = "x86_64"

def build_upstream():
    if not os.path.isfile(os.path.join(UPSTREAM_DIR, "Makefile")):
        print("=> Configuring upstream strace...")
        subprocess.run(["./bootstrap"], cwd=UPSTREAM_DIR, check=True)
        subprocess.run(["./configure", "--enable-mpers=no", "CFLAGS=-g -O2 -Wno-error", "--disable-werror"], cwd=UPSTREAM_DIR, check=True)
    print("=> Building upstream strace (make -j)...")
    try:
        cpus = multiprocessing.cpu_count()
    except NotImplementedError:
        cpus = 4
    subprocess.run(["make", f"-j{cpus}"], cwd=UPSTREAM_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def build_strace_go():
    env = os.environ.copy()
    subprocess.run(["go", "build", "-o", STRACE_GO_BIN, "./cmd/strace-go"], cwd=PROJECT_ROOT, env=env, check=True)

def build_ebpf_fixture():
    out = os.path.join(tempfile.gettempdir(), "strace-go-ebpf-semantic-fixture")
    build_fixture(FIXTURE_SRC, out)
    return out

def build_ebpf_thread_fixture():
    out = os.path.join(tempfile.gettempdir(), "strace-go-ebpf-thread-fixture")
    build_fixture(THREAD_FIXTURE_SRC, out, ["-pthread"])
    return out

def build_ebpf_attach_fixture():
    out = os.path.join(tempfile.gettempdir(), "strace-go-ebpf-attach-fixture")
    build_fixture(ATTACH_FIXTURE_SRC, out)
    return out

def build_fixture(source, output, extra_args=None):
    command = ["gcc", "-O2", "-Wall", "-Wextra"]
    if extra_args:
        command.extend(extra_args)
    command.extend(["-o", output, source])
    subprocess.run(command, check=True)
    os.chmod(output, 0o755)

def parse_json_events(stderr):
    events = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "syscall":
            events.append(ev)
    return events

def parse_lifecycle_events(stderr):
    events = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "lifecycle":
            events.append(ev)
    return events

def parse_stats_events(stderr):
    events = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "stats":
            events.append(ev)
    return events

def run_strace_go_json(args, timeout=30, debug=False):
    event_flag = "--debug-events" if debug else "--event-format=json"
    cmd = [STRACE_WRAPPER, event_flag] + args
    env = os.environ.copy()
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          errors="ignore", timeout=timeout, env=env)

def run_strace_go_text(args, timeout=30):
    cmd = [STRACE_WRAPPER] + args
    env = os.environ.copy()
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          errors="ignore", timeout=timeout, env=env)

def require(condition, failures, message):
    if not condition:
        failures.append(message)

def valid_stats_event(ev):
    return ev.get("available") is True and all(
        isinstance(ev.get(key), int) and ev.get(key) >= 0
        for key in ("ringbuf_reserve_fail", "ringbuf_copy_fail", "payload_truncated_events", "pending_update_fail", "orphan_exit", "pending_mismatch")
    )

def check_semantic_stats(stats_events, failures):
    require(len(stats_events) == 1, failures, "stats JSON event missing")
    require(all(valid_stats_event(ev) for ev in stats_events), failures, "stats JSON event has invalid counters")
    require(stats_events and stats_events[0].get("payload_truncated_events", 0) > 0,
            failures, "truncated payload stats counter missing")
    require(stats_events and stats_events[0].get("pending_mismatch", 0) == 0,
            failures, "normal semantic fixture reported pending syscall mismatch")
    require(stats_events and stats_events[0].get("pending_update_fail", 0) == 0,
            failures, "normal semantic fixture reported pending map update failure")
    require(stats_events and stats_events[0].get("orphan_exit", 0) == 0,
            failures, "normal semantic fixture reported orphan exit")

def payload_section_text(section):
    try:
        return base64.b64decode(section.get("data_base64") or "").decode("utf-8", errors="ignore")
    except Exception:
        return ""

def payload_section_bytes(section):
    try:
        return base64.b64decode(section.get("data_base64") or "")
    except Exception:
        return b""

def has_large_write_truncation(events):
    for ev in events:
        if ev.get("syscall") != "write":
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "bytes" or sec.get("direction") != "in":
                continue
            if sec.get("arg_index") != 1:
                continue
            if "ebpf-large-write-" not in payload_section_text(sec):
                continue
            copied_len = sec.get("copied_len", 0)
            user_len = sec.get("user_len", 0)
            has_flag = (ev.get("event_flags", 0) & EVENT_FLAG_TRUNCATED) != 0
            return has_flag and copied_len > 0 and copied_len < user_len
    return False

def has_path_section(events, syscall, arg_index, path_text):
    for ev in events:
        if ev.get("syscall") != syscall:
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "string" or sec.get("direction") != "in":
                continue
            if sec.get("arg_index") != arg_index:
                continue
            if path_text in payload_section_text(sec):
                return True
    return False

def has_openat_path_section(events, path_text):
    return has_path_section(events, "openat", 1, path_text)

def has_exec_payload_sections(events):
    for ev in events:
        if ev.get("syscall") != "execve" or ev.get("event_type") != "enter":
            continue
        has_args = False
        has_path = False
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") == "exec_args" and sec.get("direction") == "in" and sec.get("arg_index") == 1:
                data = payload_section_bytes(sec)
                has_args = len(data) >= 4 and data[0:4] == b"CEXE"
            if sec.get("kind") == "string" and sec.get("direction") == "in" and sec.get("arg_index") == 0:
                has_path = True
        if has_args and has_path:
            return True
    return False

def has_clock_payload_section(events):
    for ev in events:
        if ev.get("syscall") != "clock_gettime" or ev.get("event_type") != "exit":
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "struct" or sec.get("direction") != "out":
                continue
            if sec.get("arg_index") != 1:
                continue
            return sec.get("user_len") == 16 and sec.get("copied_len") == 16 and len(payload_section_bytes(sec)) == 16
    return False

def has_gettimeofday_payload_sections(events):
    for ev in events:
        if ev.get("syscall") != "gettimeofday" or ev.get("event_type") != "exit":
            continue
        has_timeval = False
        has_timezone = False
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "struct" or sec.get("direction") != "out":
                continue
            data_len = len(payload_section_bytes(sec))
            if sec.get("arg_index") == 0:
                has_timeval = sec.get("user_len") == 16 and sec.get("copied_len") == 16 and data_len == 16
            if sec.get("arg_index") == 1:
                has_timezone = sec.get("user_len") == 8 and sec.get("copied_len") == 8 and data_len == 8
        if has_timeval and has_timezone:
            return True
    return False

def has_struct_payload_section_with_direction(events, syscall, event_type, direction, arg_index, user_len):
    for ev in events:
        if ev.get("syscall") != syscall or ev.get("event_type") != event_type:
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "struct" or sec.get("direction") != direction:
                continue
            if sec.get("arg_index") != arg_index:
                continue
            return sec.get("user_len") == user_len and sec.get("copied_len") == user_len and len(payload_section_bytes(sec)) == user_len
    return False

def has_struct_payload_section(events, syscall, arg_index, user_len):
    return has_struct_payload_section_with_direction(events, syscall, "exit", "out", arg_index, user_len)

def has_fstat_payload_section(events):
    return has_struct_payload_section(events, "fstat", 1, 144)

def has_stat_payload_section(events, syscall, arg_index):
    return has_struct_payload_section(events, syscall, arg_index, 144)

def has_fstatfs_payload_section(events):
    return has_struct_payload_section(events, "fstatfs", 1, 120)

def has_statfs_payload_section(events):
    return has_struct_payload_section(events, "statfs", 1, 120)

def has_bytes_payload_section(events, syscall, arg_index, text):
    for ev in events:
        if ev.get("syscall") != syscall or ev.get("event_type") != "exit":
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "bytes" or sec.get("direction") != "out":
                continue
            if sec.get("arg_index") != arg_index:
                continue
            return text in payload_section_text(sec)
    return False

def has_sendmsg_cmsg_section(events):
    for ev in events:
        if ev.get("syscall") != "sendmsg" or ev.get("event_type") != "enter":
            continue
        for sec in ev.get("payload_sections") or []:
            if sec.get("kind") != "cmsg" or sec.get("direction") != "in":
                continue
            if sec.get("arg_index") != 1:
                continue
            data = payload_section_bytes(sec)
            return sec.get("user_len", 0) >= 16 and sec.get("copied_len", 0) >= 16 and len(data) >= 16
    return False

def check_write_only_filter(fixture, failures):
    filter_res = run_strace_go_json(["-e", "trace=write", fixture], debug=True)
    filter_events = parse_json_events(filter_res.stderr)
    filter_stats_events = parse_stats_events(filter_res.stderr)
    require(filter_res.returncode == 0, failures, f"filter fixture rc={filter_res.returncode}")
    require(len(filter_events) > 0, failures, "write-only filter produced no events")
    require(all(ev.get("syscall") == "write" for ev in filter_events),
            failures, f"write-only filter leaked events: {sorted({ev.get('syscall') for ev in filter_events})}")
    require(len(filter_stats_events) == 1 and valid_stats_event(filter_stats_events[0]),
            failures, "write-only filter stats JSON event missing or unavailable")
    return len(filter_events)

def finish_ebpf_semantic(res, failures, events, enter_events, exit_events, lifecycle_events, stats_events, filter_event_count):
    print(f"=> eBPF semantic events: {len(events)}")
    print(f"=> eBPF semantic enter/exit: {len(enter_events)}/{len(exit_events)}")
    print(f"=> eBPF lifecycle events: {len(lifecycle_events)}")
    if stats_events:
        print(f"=> eBPF ringbuf reserve failures: {stats_events[0].get('ringbuf_reserve_fail')}")
        print(f"=> eBPF ringbuf copy failures: {stats_events[0].get('ringbuf_copy_fail')}")
        print(f"=> eBPF payload truncated events: {stats_events[0].get('payload_truncated_events')}")
        print(f"=> eBPF pending update failures: {stats_events[0].get('pending_update_fail')}")
        print(f"=> eBPF orphan exits: {stats_events[0].get('orphan_exit')}")
        print(f"=> eBPF pending mismatches: {stats_events[0].get('pending_mismatch')}")
    print(f"=> eBPF write-only events: {filter_event_count}")
    if failures:
        print("\n=== EBPF SEMANTIC FAILURES ===")
        for failure in failures:
            print(f"FAIL: {failure}")
        print("\n--- stderr tail ---")
        print("\n".join(res.stderr.splitlines()[-40:]))
        return 1
    print("PASS: ebpf-semantic")
    return 0

def collect_semantic_events(fixture):
    trace_set = "open,openat,read,write,pread64,pwrite64,close,stat,lstat,fstat,newfstatat,statfs,fstatfs,getcwd,readlink,readlinkat,pipe,pipe2,socketpair,uname,sysinfo,getrlimit,setrlimit,prlimit64,arch_prctl,get_robust_list,sendfile,copy_file_range,getitimer,setitimer,clock_settime,settimeofday,adjtimex,nanosleep,clock_nanosleep,futex,futex_wait,futex_waitv,futex_requeue,sendmsg,execve,exit,exit_group,clock_gettime,gettimeofday"
    res = run_strace_go_json(["-f", "-e", f"trace={trace_set}", fixture])
    events = parse_json_events(res.stderr)
    lifecycle_events = parse_lifecycle_events(res.stderr)
    stats_events = parse_stats_events(res.stderr)
    enter_events = [ev for ev in events if ev.get("event_type") == "enter"]
    exit_events = [ev for ev in events if ev.get("event_type") == "exit"]
    return res, events, lifecycle_events, stats_events, enter_events, exit_events

def collect_thread_lifecycle_events(fixture):
    res = run_strace_go_json(["-f", "-e", "trace=getpid,exit,exit_group", fixture])
    events = parse_json_events(res.stderr)
    lifecycle_events = parse_lifecycle_events(res.stderr)
    stats_events = parse_stats_events(res.stderr)
    enter_events = [ev for ev in events if ev.get("event_type") == "enter"]
    exit_events = [ev for ev in events if ev.get("event_type") == "exit"]
    return res, events, lifecycle_events, stats_events, enter_events, exit_events

def collect_thread_unfinished_text(fixture):
    return run_strace_go_text([
        "-f", "-e", "trace=read,getpid,write,exit,exit_group", fixture
    ])

def collect_attach_orphan_stats(fixture):
    target = subprocess.Popen(
        [fixture], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    tracer = None
    try:
        ready = target.stdout.readline()
        if "attach-fixture-ready" not in ready:
            raise RuntimeError(f"attach fixture did not become ready: {ready!r}")

        tracer_cmd = [
            STRACE_WRAPPER, "--event-format=json", "-p", str(target.pid),
            "-e", "trace=read,exit,exit_group",
        ]
        tracer = subprocess.Popen(
            tracer_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=os.environ.copy(),
        )
        # BPF load and attach must finish before releasing the in-flight read.
        time.sleep(5.0)
        if tracer.poll() is not None:
            raise RuntimeError(f"attach tracer exited before release: rc={tracer.returncode}")
        os.kill(target.pid, signal.SIGUSR1)

        target_stdout, target_stderr = target.communicate(timeout=10)
        tracer_stdout, tracer_stderr = tracer.communicate(timeout=30)
        tracer_result = subprocess.CompletedProcess(
            tracer_cmd, tracer.returncode, tracer_stdout, tracer_stderr,
        )
        return target.returncode, target_stdout, target_stderr, tracer_result
    finally:
        if target.poll() is None:
            target.kill()
            target.wait(timeout=5)
        if tracer is not None and tracer.poll() is None:
            tracer.kill()
            tracer.wait(timeout=5)

def run_ebpf_semantic(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_ebpf_fixture()

    failures = []

    res, events, lifecycle_events, stats_events, enter_events, exit_events = collect_semantic_events(fixture)
    thread_fixture = build_ebpf_thread_fixture()
    thread_res, thread_events, thread_lifecycle_events, thread_stats_events, thread_enter_events, thread_exit_events = collect_thread_lifecycle_events(thread_fixture)
    thread_text_res = collect_thread_unfinished_text(thread_fixture)
    thread_text = thread_text_res.stderr
    attach_fixture = build_ebpf_attach_fixture()
    attach_target_rc, attach_stdout, attach_stderr, attach_res = collect_attach_orphan_stats(attach_fixture)
    attach_stats_events = parse_stats_events(attach_res.stderr)
    names = {ev.get("syscall") for ev in events}
    lifecycle_actions = {ev.get("action") for ev in lifecycle_events}

    require(res.returncode == 0, failures, f"semantic fixture rc={res.returncode}")
    require("ebpf-fixture-write" in res.stdout, failures, "fixture stdout marker missing")
    require(len(events) > 0, failures, "no JSON syscall events decoded")
    require(len(enter_events) > 0, failures, "no syscall enter JSON events decoded")
    require(len(exit_events) > 0, failures, "no syscall exit JSON events decoded")
    check_semantic_stats(stats_events, failures)
    require("write" in names, failures, "write event missing")
    require("pwrite64" in names, failures, "pwrite64 event missing")
    require("pread64" in names, failures, "pread64 event missing")
    require(("openat" in names) or ("open" in names), failures, "open/openat event missing")
    require("read" in names, failures, "read event missing")
    require("close" in names, failures, "close event missing")
    require("stat" in names, failures, "stat event missing")
    require("lstat" in names, failures, "lstat event missing")
    require("fstat" in names, failures, "fstat event missing")
    require("newfstatat" in names, failures, "newfstatat event missing")
    require("statfs" in names, failures, "statfs event missing")
    require("fstatfs" in names, failures, "fstatfs event missing")
    require("getcwd" in names, failures, "getcwd event missing")
    require("readlink" in names, failures, "readlink event missing")
    require("readlinkat" in names, failures, "readlinkat event missing")
    require("pipe" in names, failures, "pipe event missing")
    require("pipe2" in names, failures, "pipe2 event missing")
    require("socketpair" in names, failures, "socketpair event missing")
    require("uname" in names, failures, "uname event missing")
    require("sysinfo" in names, failures, "sysinfo event missing")
    require("getrlimit" in names, failures, "getrlimit event missing")
    require("setrlimit" in names, failures, "setrlimit event missing")
    require("prlimit64" in names, failures, "prlimit64 event missing")
    require("arch_prctl" in names, failures, "arch_prctl event missing")
    require("get_robust_list" in names, failures, "get_robust_list event missing")
    require("sendfile" in names, failures, "sendfile event missing")
    require("copy_file_range" in names, failures, "copy_file_range event missing")
    require("getitimer" in names, failures, "getitimer event missing")
    require("setitimer" in names, failures, "setitimer event missing")
    require("clock_settime" in names, failures, "clock_settime event missing")
    require("settimeofday" in names, failures, "settimeofday event missing")
    require("adjtimex" in names, failures, "adjtimex event missing")
    require("nanosleep" in names, failures, "nanosleep event missing")
    require("clock_nanosleep" in names, failures, "clock_nanosleep event missing")
    require("futex" in names, failures, "futex event missing")
    require("futex_wait" in names, failures, "futex_wait event missing")
    require("futex_waitv" in names, failures, "futex_waitv event missing")
    require("futex_requeue" in names, failures, "futex_requeue event missing")
    require("sendmsg" in names, failures, "sendmsg event missing")
    require("clock_gettime" in names, failures, "clock_gettime event missing")
    require("gettimeofday" in names, failures, "gettimeofday event missing")
    require("execve" in names, failures, "child execve event missing; fork following may be broken")
    require(any(ev.get("syscall") in ("exit", "exit_group") and ev.get("event_type") == "exit" and ev.get("paired_enter") for ev in exit_events),
            failures, "exit/exit_group direct exit event was not paired with enter state")
    require(has_openat_path_section(events, "/tmp/strace-go-ebpf-missing-file"),
            failures, "openat path payload section missing from JSON event")
    require(has_path_section(events, "statfs", 0, "/proc/self"),
            failures, "statfs path payload section missing from JSON event")
    require(has_path_section(events, "stat", 0, "/proc/self"),
            failures, "stat path payload section missing from JSON event")
    require(has_path_section(events, "lstat", 0, "/proc/self"),
            failures, "lstat path payload section missing from JSON event")
    require(has_path_section(events, "newfstatat", 1, "/proc/self"),
            failures, "newfstatat path payload section missing from JSON event")
    require(has_path_section(events, "readlink", 0, "/tmp/strace-go-ebpf-readlink-"),
            failures, "readlink path payload section missing from JSON event")
    require(has_path_section(events, "readlinkat", 1, "/tmp/strace-go-ebpf-readlink-"),
            failures, "readlinkat path payload section missing from JSON event")
    require(has_exec_payload_sections(events), failures, "execve argv/envp and filename payload sections missing from JSON event")
    require(has_clock_payload_section(events), failures, "clock_gettime OUT timespec payload section missing from JSON event")
    require(has_gettimeofday_payload_sections(events), failures, "gettimeofday OUT timeval/timezone payload sections missing from JSON event")
    require(has_fstat_payload_section(events), failures, "fstat OUT stat payload section missing from JSON event")
    require(has_stat_payload_section(events, "stat", 1), failures, "stat OUT stat payload section missing from JSON event")
    require(has_stat_payload_section(events, "lstat", 1), failures, "lstat OUT stat payload section missing from JSON event")
    require(has_stat_payload_section(events, "newfstatat", 2), failures, "newfstatat OUT stat payload section missing from JSON event")
    require(has_statfs_payload_section(events), failures, "statfs OUT statfs payload section missing from JSON event")
    require(has_fstatfs_payload_section(events), failures, "fstatfs OUT statfs payload section missing from JSON event")
    require(has_bytes_payload_section(events, "getcwd", 0, "strace-go"),
            failures, "getcwd OUT cwd payload section missing from JSON event")
    require(has_bytes_payload_section(events, "readlink", 1, "/proc/self"),
            failures, "readlink OUT target payload section missing from JSON event")
    require(has_bytes_payload_section(events, "readlinkat", 2, "/proc/self"),
            failures, "readlinkat OUT target payload section missing from JSON event")
    require(has_struct_payload_section(events, "pipe", 0, 8),
            failures, "pipe OUT fd-array payload section missing from JSON event")
    require(has_struct_payload_section(events, "pipe2", 0, 8),
            failures, "pipe2 OUT fd-array payload section missing from JSON event")
    require(has_struct_payload_section(events, "socketpair", 3, 8),
            failures, "socketpair OUT fd-array payload section missing from JSON event")
    require(has_struct_payload_section(events, "uname", 0, 390),
            failures, "uname OUT utsname payload section missing from JSON event")
    require(has_struct_payload_section(events, "sysinfo", 0, 112),
            failures, "sysinfo OUT struct payload section missing from JSON event")
    require(has_struct_payload_section(events, "getrlimit", 1, 16),
            failures, "getrlimit OUT rlimit payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "setrlimit", "enter", "in", 1, 16),
            failures, "setrlimit IN rlimit payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "prlimit64", "enter", "in", 2, 16),
            failures, "prlimit64 IN new_rlimit payload section missing from JSON event")
    require(has_struct_payload_section(events, "prlimit64", 3, 16),
            failures, "prlimit64 OUT old_rlimit payload section missing from JSON event")
    require(has_struct_payload_section(events, "arch_prctl", 1, 8),
            failures, "arch_prctl OUT word payload section missing from JSON event")
    require(has_struct_payload_section(events, "get_robust_list", 1, 8),
            failures, "get_robust_list OUT head payload section missing from JSON event")
    require(has_struct_payload_section(events, "get_robust_list", 2, 8),
            failures, "get_robust_list OUT len payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "sendfile", "enter", "in", 2, 8),
            failures, "sendfile IN offset payload section missing from JSON event")
    require(has_struct_payload_section(events, "sendfile", 2, 8),
            failures, "sendfile OUT offset payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "copy_file_range", "enter", "in", 1, 8),
            failures, "copy_file_range IN off_in payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "copy_file_range", "enter", "in", 3, 8),
            failures, "copy_file_range IN off_out payload section missing from JSON event")
    require(has_struct_payload_section(events, "getitimer", 1, 32),
            failures, "getitimer OUT itimerval payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "setitimer", "enter", "in", 1, 32),
            failures, "setitimer IN itimerval payload section missing from JSON event")
    require(has_struct_payload_section(events, "setitimer", 2, 32),
            failures, "setitimer OUT itimerval payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "clock_settime", "enter", "in", 1, 16),
            failures, "clock_settime IN timespec payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "settimeofday", "enter", "in", 0, 16),
            failures, "settimeofday IN timeval payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "settimeofday", "enter", "in", 1, 8),
            failures, "settimeofday IN timezone payload section missing from JSON event")
    require(has_struct_payload_section(events, "adjtimex", 0, 208),
            failures, "adjtimex OUT timex payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "nanosleep", "enter", "in", 0, 16),
            failures, "nanosleep IN timespec payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "clock_nanosleep", "enter", "in", 2, 16),
            failures, "clock_nanosleep IN timespec payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "futex", "enter", "in", 3, 16),
            failures, "futex IN timeout payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "futex_wait", "enter", "in", 4, 16),
            failures, "futex_wait IN timeout payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "futex_waitv", "enter", "in", 0, 48),
            failures, "futex_waitv IN waiters payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "futex_waitv", "enter", "in", 3, 16),
            failures, "futex_waitv IN timeout payload section missing from JSON event")
    require(has_struct_payload_section_with_direction(events, "futex_requeue", "enter", "in", 0, 48),
            failures, "futex_requeue IN waiters payload section missing from JSON event")
    require(has_sendmsg_cmsg_section(events),
            failures, "sendmsg IN cmsg payload section missing from JSON event")
    require(any(ev.get("syscall") == "write" for ev in enter_events), failures, "write enter event missing")
    require(any(ev.get("syscall") == "write" for ev in exit_events), failures, "write exit event missing")
    require(any(ev.get("syscall") == "read" for ev in enter_events), failures, "read enter event missing")
    require(any(ev.get("syscall") == "read" for ev in exit_events), failures, "read exit event missing")
    require(any(ev.get("syscall") == "write" and ev.get("paired_enter") for ev in exit_events),
            failures, "write exit event was not paired with enter state")
    require(any(ev.get("syscall") == "read" and ev.get("paired_enter") for ev in exit_events),
            failures, "read exit event was not paired with enter state")
    require(any(ev.get("syscall") == "pwrite64" and ev.get("paired_enter") for ev in exit_events),
            failures, "pwrite64 exit event was not paired with enter state")
    require(any(ev.get("syscall") == "pread64" and ev.get("paired_enter") for ev in exit_events),
            failures, "pread64 exit event was not paired with enter state")
    require(any(ev.get("failed") and ev.get("errno") == 2 for ev in events), failures, "ENOENT failed-open event missing")
    require(any(ev.get("syscall") == "write" and "ebpf-fixture-write" in " ".join(ev.get("arg_text") or []) for ev in events),
            failures, "write payload text missing from JSON arg_text")
    require(any(ev.get("syscall") == "write" and any(
                sec.get("kind") == "bytes" and
                sec.get("direction") == "in" and
                sec.get("arg_index") == 1 and
                "ebpf-fixture-write" in payload_section_text(sec)
            for sec in ev.get("payload_sections") or []) for ev in events),
            failures, "write payload section missing from JSON event")
    require(has_large_write_truncation(events), failures, "large write payload truncation metadata missing")
    require(any(ev.get("syscall") == "pwrite64" and any(
                sec.get("kind") == "bytes" and
                sec.get("direction") == "in" and
                sec.get("arg_index") == 1 and
                "ebpf-fixture-pwrite" in payload_section_text(sec)
            for sec in ev.get("payload_sections") or []) for ev in events),
            failures, "pwrite64 payload section missing from JSON event")
    require(any(ev.get("syscall") == "pread64" and any(
                sec.get("kind") == "bytes" and
                sec.get("direction") == "out" and
                sec.get("arg_index") == 1 and
                "ebpf-fixture-pwrite" in payload_section_text(sec)
            for sec in ev.get("payload_sections") or []) for ev in events),
            failures, "pread64 payload section missing from JSON event")
    require(len({ev.get("pid") for ev in events}) >= 2, failures, "forked child pid events missing")
    require("fork" in lifecycle_actions, failures, "fork lifecycle event missing")
    require("exec" in lifecycle_actions, failures, "exec lifecycle event missing")
    require(("exit" in lifecycle_actions) or ("free" in lifecycle_actions), failures, "exit/free lifecycle event missing")
    require(any(ev.get("action") == "fork" and ev.get("task_tid") == ev.get("arg1") and ev.get("parent_tid") == ev.get("arg0") and ev.get("alive") for ev in lifecycle_events),
            failures, "fork lifecycle task state missing child/parent/alive fields")
    require(any(ev.get("action") == "exec" and ev.get("execed") and ev.get("alive") for ev in lifecycle_events),
            failures, "exec lifecycle task state missing execed/alive fields")
    require(any(ev.get("action") == "exec" and os.path.basename(ev.get("filename") or "") == "true" for ev in lifecycle_events),
            failures, "exec lifecycle filename snapshot missing")
    require(any(ev.get("action") in ("exit", "free") and ev.get("alive") is False for ev in lifecycle_events),
            failures, "exit/free lifecycle task state did not mark task dead")

    thread_syscalls = [ev for ev in thread_events if ev.get("syscall") == "getpid" and ev.get("tid") != ev.get("pid")]
    thread_fork_lifecycle = [ev for ev in thread_lifecycle_events if ev.get("action") == "fork"]
    thread_lifecycle = [ev for ev in thread_lifecycle_events
                        if ev.get("action") in ("exit", "free") and ev.get("tid") != ev.get("pid")]
    require(thread_res.returncode == 0, failures, f"thread fixture rc={thread_res.returncode}")
    require("thread-fixture-ok" in thread_res.stdout, failures, "thread fixture stdout marker missing")
    require(len(thread_stats_events) == 1 and valid_stats_event(thread_stats_events[0]),
            failures, "thread fixture stats JSON event missing or unavailable")
    require(thread_syscalls, failures, "non-leader thread getpid events missing")
    require(any(ev.get("event_type") == "exit" and ev.get("paired_enter") for ev in thread_syscalls),
            failures, "non-leader thread getpid exit was not paired with enter")
    require(thread_lifecycle, failures, "non-leader thread exit/free lifecycle identity missing")
    require(any(ev.get("task_tid") == ev.get("arg1") and not ev.get("task_tgid")
                for ev in thread_fork_lifecycle),
            failures, "thread fork lifecycle must not guess child TGID from child TID")
    require(any(ev.get("action") in ("exit", "free") and ev.get("tid") != ev.get("pid") and
                ev.get("task_tgid") == ev.get("pid") for ev in thread_lifecycle),
            failures, "thread exit/free lifecycle did not resolve child TGID")
    require(thread_text_res.returncode == 0, failures, f"thread text fixture rc={thread_text_res.returncode}")
    require("thread-fixture-ok" in thread_text_res.stdout, failures, "thread text fixture stdout marker missing")
    require("read(" in thread_text and "<unfinished ...>" in thread_text,
            failures, "thread text fixture did not produce read unfinished output")
    require("<... read resumed>)" in thread_text,
            failures, "thread text fixture did not produce read resumed output")
    require(attach_target_rc == 0, failures, f"attach fixture rc={attach_target_rc}")
    require("attach-fixture-ok" in attach_stdout, failures, "attach fixture stdout marker missing")
    require(attach_res.returncode == 0, failures, f"attach tracer rc={attach_res.returncode}")
    require(len(attach_stats_events) == 1 and valid_stats_event(attach_stats_events[0]),
            failures, "attach orphan stats JSON event missing or unavailable")
    require(attach_stats_events and attach_stats_events[0].get("orphan_exit", 0) > 0,
            failures, "attach-in-flight read did not produce orphan_exit diagnostics")
    print(f"=> eBPF thread semantic events: {len(thread_events)}")
    print(f"=> eBPF thread lifecycle events: {len(thread_lifecycle_events)}")
    unfinished_lines = sum(1 for line in thread_text.splitlines() if "<unfinished ...>" in line)
    print(f"=> eBPF thread unfinished text lines: {unfinished_lines}")
    print(f"=> eBPF attach orphan exits: {attach_stats_events[0].get('orphan_exit') if attach_stats_events else 'unavailable'}")
    filter_event_count = check_write_only_filter(fixture, failures)

    return finish_ebpf_semantic(
        res, failures, events, enter_events, exit_events, lifecycle_events, stats_events, filter_event_count
    )

def run_ebpf_perf(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_ebpf_fixture()

    start = time.monotonic()
    res = run_strace_go_json(["-e", "trace=getpid", fixture, "perf"], timeout=60)
    elapsed = time.monotonic() - start
    events = parse_json_events(res.stderr)
    stats_events = parse_stats_events(res.stderr)
    getpid_events = [ev for ev in events if ev.get("syscall") == "getpid"]
    getpid_enter_events = [ev for ev in getpid_events if ev.get("event_type") == "enter"]
    getpid_exit_events = [ev for ev in getpid_events if ev.get("event_type") == "exit"]

    print("=== EBPF PERF ===")
    print(f"returncode: {res.returncode}")
    print(f"elapsed_sec: {elapsed:.6f}")
    print(f"json_events: {len(events)}")
    print(f"getpid_events: {len(getpid_events)}")
    print(f"getpid_enter_events: {len(getpid_enter_events)}")
    print(f"getpid_exit_events: {len(getpid_exit_events)}")
    if stats_events:
        print(f"ringbuf_reserve_fail: {stats_events[0].get('ringbuf_reserve_fail')}")
        print(f"ringbuf_copy_fail: {stats_events[0].get('ringbuf_copy_fail')}")
        print(f"payload_truncated_events: {stats_events[0].get('payload_truncated_events')}")
        print(f"orphan_exit: {stats_events[0].get('orphan_exit')}")
        print(f"pending_mismatch: {stats_events[0].get('pending_mismatch')}")
    if elapsed > 0:
        print(f"events_per_sec: {len(getpid_exit_events) / elapsed:.2f}")

    if res.returncode != 0 or len(stats_events) != 1 or not valid_stats_event(stats_events[0]) or len(getpid_exit_events) < 1000 or len(getpid_enter_events) < 1000 or not all(ev.get("paired_enter") for ev in getpid_exit_events):
        print("\n=== EBPF PERF FAILURE ===")
        print("\n".join(res.stderr.splitlines()[-40:]))
        return 1
    return 0

def get_tests(suite):
    valid_tests = []
    if not os.path.exists(TESTS_DIR):
        print(f"Tests dir {TESTS_DIR} not found.")
        return []
    
    for f in os.listdir(TESTS_DIR):
        if f.endswith(".test") and not f.endswith(".sh"):
            # Exclude tests that need special handling or are known to freeze
            if f in ["strace-k.test"]:
                continue
            valid_tests.append(f)
    valid_tests.sort()
    
    if suite == "small":
        return [t for t in SMOKE_TESTS if t in valid_tests]
    elif suite == "more":
        return [t for t in MORE_TESTS if t in valid_tests]
    elif suite == "upstream-reference":
        return [t for t in UPSTREAM_REFERENCE_TESTS if t in valid_tests]
    elif suite == "all":
        return valid_tests
    else:
        # Fallback to single test matching
        return [t for t in valid_tests if suite in t]


def run_test(t):
    bin_name = t.replace(".test", "").replace(".gen", "")
    subprocess.run(["make", bin_name], cwd=TESTS_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if bin_name == "sleep-timing":
        # The generated tests Makefile builds this helper via the builtin .c
        # rule without the src/libtests flags, so compile it explicitly.
        subprocess.run(
            [
                "gcc", "-g", "-O2", "-Wno-error",
                "-I../src", "-I.",
                "-isystem", "./bundled/linux/arch/x86/include/uapi",
                "-isystem", "./bundled/linux/include/uapi",
                "sleep-timing.c", "libtests.a", "-o", "sleep-timing",
            ],
            cwd=TESTS_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    import tempfile
    out_fd, out_path = tempfile.mkstemp()
    err_fd, err_path = tempfile.mkstemp()
    
    try:
        with os.fdopen(out_fd, 'w') as out_f, os.fdopen(err_fd, 'w') as err_f:
            proc = subprocess.Popen(
                [f"./{t}"],
                cwd=TESTS_DIR,
                stdin=subprocess.DEVNULL,
                stdout=out_f,
                stderr=err_f,
                start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                # Kill the whole test session (shell + sudo + strace-go) so
                # hung tests do not leave orphaned tracers running.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait(timeout=5)
                rc = 124
                
        with open(out_path, 'r', errors='ignore') as f:
            stdout_str = f.read()
        with open(err_path, 'r', errors='ignore') as f:
            stderr_str = f.read()
            
        return {
            "test": t,
            "success": rc == 0,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "rc": rc
        }
    finally:
        os.remove(out_path)
        os.remove(err_path)

def expected_failures_for_suite(suite):
    if suite == "upstream-reference":
        return UPSTREAM_REFERENCE_EXPECTED_FAILURES
    if suite == "more":
        return MORE_EXPECTED_FAILURES
    return {}

def classify_test_result(result, expected_failures):
    reason = expected_failures.get(result["test"], "")
    if result["rc"] == 77:
        return "skip", ""
    if result["success"]:
        if reason:
            return "xpass", reason
        return "pass", ""
    if reason:
        return "xfail", reason
    return "fail", ""

def outcome_label(outcome, reason):
    if outcome == "pass":
        return "PASS"
    if outcome == "skip":
        return "SKIP"
    if outcome == "xfail":
        return f"XFAIL ({reason})"
    if outcome == "xpass":
        return f"XPASS ({reason})"
    return "FAIL"

def new_result_counts():
    return {"pass": 0, "fail": 0, "skip": 0, "xfail": 0, "xpass": 0}

def record_test_result(result, expected_failures, counts, failed_list, xfailed_list, xpassed_list):
    outcome, reason = classify_test_result(result, expected_failures)
    counts[outcome] += 1
    if outcome == "fail":
        failed_list.append(result)
    elif outcome == "xfail":
        xfailed_list.append((result, reason))
    elif outcome == "xpass":
        xpassed_list.append((result, reason))
    return outcome, reason

def print_summary(counts):
    total = sum(counts.values())
    print("\n=== SUMMARY ===")
    print(f"Passed:  {counts['pass']}")
    print(f"Failed:  {counts['fail']}")
    print(f"Skipped: {counts['skip']}")
    print(f"XFailed: {counts['xfail']}")
    print(f"XPassed: {counts['xpass']}")
    print(f"Total:   {total}")

def print_expected_outcomes(xfailed_list, xpassed_list):
    if xfailed_list:
        print("\n=== EXPECTED FAILURES ===")
        for res, reason in xfailed_list:
            print(f"{res['test']}: {reason}")
    if xpassed_list:
        print("\n=== UNEXPECTED PASSES ===")
        for res, reason in xpassed_list:
            print(f"{res['test']}: {reason}")

def print_failure_details(failed_list):
    if not failed_list:
        return
    print("\n=== FAIL DETAILS ===")
    for res in failed_list:
        print(f"\n--- {res['test']} ---")
        if res["stdout"]:
            print("STDOUT:")
            lines = res["stdout"].split("\n")[:15]
            print("\n".join(lines))
        if res["stderr"]:
            print("STDERR:")
            print(res["stderr"])

def main():
    args = parse_args()
    setup_env()

    if args.suite == "ebpf-semantic":
        sys.exit(run_ebpf_semantic(args))
    if args.suite == "ebpf-perf":
        sys.exit(run_ebpf_perf(args))
    
    if not args.skip_build:
        build_upstream()
        
    tests_to_run = get_tests(args.suite)
    if args.filter:
        final_list = [t for t in tests_to_run if t == args.filter]
        tests_to_run = final_list
    if args.limit > 0:
        tests_to_run = tests_to_run[:args.limit]
        
    print(f"=> Running {len(tests_to_run)} tests from '{args.suite}' suite...")
    
    counts = new_result_counts()
    failed_list = []
    xfailed_list = []
    xpassed_list = []
    expected_failures = expected_failures_for_suite(args.suite)
    
    if args.parallel > 1:
        print(f"=> Using {args.parallel} parallel workers.")
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {executor.submit(run_test, t): t for t in tests_to_run}
            for future in as_completed(futures):
                result = future.result()
                t = result["test"]
                outcome, reason = record_test_result(result, expected_failures, counts, failed_list, xfailed_list, xpassed_list)
                print(f"{outcome_label(outcome, reason)}: {t}")
    else:
        for t in tests_to_run:
            print(f"Running {t}... ", end="", flush=True)
            result = run_test(t)
            outcome, reason = record_test_result(result, expected_failures, counts, failed_list, xfailed_list, xpassed_list)
            print(outcome_label(outcome, reason))

    print_summary(counts)
    print_expected_outcomes(xfailed_list, xpassed_list)
    print_failure_details(failed_list)

    if counts["fail"] > 0 or counts["xpass"] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
