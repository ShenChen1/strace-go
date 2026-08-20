#!/usr/bin/env python3
import json
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from ebpf_event_oracles import (
    parse_json_events,
    parse_lifecycle_events,
    parse_ready_events,
    parse_stats_events,
)
from ebpf_fixture_build import build_named_fixture
from ebpf_cloexec_suite import run_cloexec_semantic
from ebpf_epoll_suite import run_epoll_semantic
from ebpf_signalfd_suite import run_signalfd_semantic
from ebpf_semantic_checks import (
    check_semantic_context,
    require,
    valid_stats_event,
)
from ebpf_semantic_summary import print_semantic_summary
from ebpf_sockopt_suite import run_sockopt_semantic

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
STRACE_WRAPPER = os.path.join(SCRIPT_DIR, "strace-sudo.sh")
STRACE_GO_BIN = os.path.join(PROJECT_ROOT, "strace-go")
FIXTURE_SOURCES = (
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_semantic_fixture.c"),
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_semantic_fs_workloads.c"),
    os.path.join(SCRIPT_DIR, "fixtures", "ebpf_semantic_runtime_workloads.c"),
)
THREAD_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_thread_fixture.c")
ATTACH_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_attach_fixture.c")
ATTACH_THREAD_FIXTURE_SRC = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_attach_thread_fixture.c"
)
MOUNT_QUERY_FIXTURE_SRC = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_mount_query_fixture.c"
)
MOUNT_PATH_FIXTURE_SRC = os.path.join(
    SCRIPT_DIR, "fixtures", "ebpf_mount_path_fixture.c"
)
DIRENT_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_dirent_fixture.c")
MMSG_FIXTURE_SRC = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_mmsg_fixture.c")
ATTACH_READY_TIMEOUT_SECONDS = 30


@dataclass
class EventCapture:
    result: subprocess.CompletedProcess
    events: list
    lifecycle_events: list
    stats_events: list

    @property
    def enter_events(self):
        return [event for event in self.events if event.get("event_type") == "enter"]

    @property
    def exit_events(self):
        return [event for event in self.events if event.get("event_type") == "exit"]


@dataclass
class AttachCapture:
    target_rc: int
    target_stdout: str
    target_stderr: str
    result: subprocess.CompletedProcess
    stats_events: list


@dataclass
class AttachThreadCapture:
    target_rc: int
    target_stdout: str
    target_stderr: str
    attach_tid: int
    result: subprocess.CompletedProcess
    events: list
    stats_events: list


@dataclass
class SemanticContext:
    main: EventCapture
    fcntl: EventCapture
    dirent: EventCapture
    mmsg: EventCapture
    mount_query: EventCapture
    mount_path: EventCapture
    mount_path_filtered: EventCapture
    thread: EventCapture
    thread_text: subprocess.CompletedProcess
    attach: AttachCapture
    attach_thread: AttachThreadCapture


def build_strace_go():
    subprocess.run(
        ["go", "build", "-o", STRACE_GO_BIN, "./cmd/strace-go"],
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
        check=True,
    )


def build_ebpf_fixture():
    return build_named_fixture("strace-go-ebpf-semantic-fixture", FIXTURE_SOURCES)


def build_ebpf_thread_fixture():
    return build_named_fixture(
        "strace-go-ebpf-thread-fixture", (THREAD_FIXTURE_SRC,), ["-pthread"]
    )


def build_ebpf_attach_fixture():
    return build_named_fixture("strace-go-ebpf-attach-fixture", (ATTACH_FIXTURE_SRC,))


def build_ebpf_attach_thread_fixture():
    return build_named_fixture(
        "strace-go-ebpf-attach-thread-fixture",
        (ATTACH_THREAD_FIXTURE_SRC,),
        ["-pthread"],
    )


def build_ebpf_mount_query_fixture():
    return build_named_fixture(
        "strace-go-ebpf-mount-query-fixture", (MOUNT_QUERY_FIXTURE_SRC,)
    )


def build_ebpf_mount_path_fixture():
    return build_named_fixture(
        "strace-go-ebpf-mount-path-fixture", (MOUNT_PATH_FIXTURE_SRC,)
    )


def build_ebpf_dirent_fixture():
    return build_named_fixture("strace-go-ebpf-dirent-fixture", (DIRENT_FIXTURE_SRC,))


def build_ebpf_mmsg_fixture():
    return build_named_fixture("strace-go-ebpf-mmsg-fixture", (MMSG_FIXTURE_SRC,))

def run_strace_go_json(args, timeout=30, debug=False, phases=False):
    if debug:
        event_flag = "--debug-events"
    elif phases:
        event_flag = "--debug-phases"
    else:
        event_flag = "--event-format=json"
    command = [STRACE_WRAPPER, event_flag] + args
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=timeout,
        env=os.environ.copy(),
    )


def run_strace_go_none(args, timeout=30):
    command = [STRACE_WRAPPER, "--debug-phases", "--event-format=none"] + args
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=timeout,
        env=os.environ.copy(),
    )


def run_strace_go_text(args, timeout=30):
    return subprocess.run(
        [STRACE_WRAPPER] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        timeout=timeout,
        env=os.environ.copy(),
    )


def event_capture(result):
    events = parse_json_events(result.stderr)
    return EventCapture(
        result=result,
        events=events,
        lifecycle_events=parse_lifecycle_events(result.stderr),
        stats_events=parse_stats_events(result.stderr),
    )


def collect_semantic_events(fixture):
    trace_set = (
        "open,openat,openat2,read,write,pread64,pwrite64,close,stat,lstat,fstat,"
        "newfstatat,statfs,fstatfs,getcwd,readlink,readlinkat,pipe,pipe2,"
        "socketpair,dup,dup2,dup3,fcntl,close_range,uname,sysinfo,getrlimit,setrlimit,prlimit64,arch_prctl,"
        "get_robust_list,sendfile,copy_file_range,getitimer,setitimer,"
        "clock_settime,settimeofday,adjtimex,nanosleep,clock_nanosleep,"
        "futex,futex_wait,futex_waitv,futex_requeue,sendmsg,execve,exit,"
        "exit_group,clock_gettime,gettimeofday"
    )
    return event_capture(run_strace_go_json(["-f", "-e", f"trace={trace_set}", fixture]))


def collect_thread_lifecycle_events(fixture):
    result = run_strace_go_json(
        ["-f", "-e", "trace=getpid,execve,exit,exit_group", fixture]
    )
    return event_capture(result)


def collect_mount_query_events(fixture):
    return event_capture(
        run_strace_go_json(["-e", "trace=statmount,listmount", fixture])
    )


def collect_mount_path_events(fixture, trace_path=None):
    args = ["-e", "trace=open_tree,move_mount"]
    if trace_path:
        args = ["-P", trace_path] + args
    return event_capture(run_strace_go_json(args + [fixture]))


def collect_dirent_events(fixture):
    return event_capture(
        run_strace_go_json(["-e", "trace=getdents,getdents64", fixture])
    )


def collect_mmsg_events(fixture):
    return event_capture(
        run_strace_go_json(["-e", "trace=sendmmsg,recvmmsg", fixture])
    )


def collect_thread_unfinished_text(fixture):
    return run_strace_go_text(
        ["-f", "-e", "trace=read,getpid,write,execve,exit,exit_group", fixture]
    )


def decode_debug_event(line):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return {}
    return event if isinstance(event, dict) else {}


def ready_error(process, captured, reason):
    return RuntimeError(
        f"attach tracer {reason}: rc={process.returncode}\n"
        f"stderr:\n{captured.decode('utf-8', errors='ignore')}"
    )


def wait_for_debug_ready(process, timeout=ATTACH_READY_TIMEOUT_SECONDS):
    if process.stderr is None:
        raise RuntimeError("attach tracer has no stderr pipe")
    deadline = time.monotonic() + timeout
    captured = bytearray()
    pending = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stderr.fileno(), selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.poll()
                raise ready_error(process, captured, "readiness timed out")
            if not selector.select(remaining):
                process.poll()
                raise ready_error(process, captured, "readiness timed out")
            chunk = os.read(process.stderr.fileno(), 4096)
            if not chunk:
                try:
                    process.wait(timeout=min(1, max(remaining, 0.1)))
                    reason = "exited before readiness"
                except subprocess.TimeoutExpired:
                    process.poll()
                    reason = "closed stderr before readiness"
                raise ready_error(process, captured, reason)
            captured.extend(chunk)
            pending.extend(chunk)
            while b"\n" in pending:
                raw_line, _, pending = pending.partition(b"\n")
                event = decode_debug_event(raw_line.decode("utf-8", errors="ignore"))
                if event.get("type") == "ready":
                    return captured.decode("utf-8", errors="ignore")
    finally:
        selector.close()


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.kill()
    process.wait(timeout=5)


def collect_attach_orphan_stats(fixture):
    target = subprocess.Popen(
        [fixture],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    tracer = None
    try:
        ready = target.stdout.readline()
        if "attach-fixture-ready" not in ready:
            raise RuntimeError(f"attach fixture did not become ready: {ready!r}")
        command = [
            STRACE_WRAPPER,
            "--debug-events",
            "-p",
            str(target.pid),
            "-e",
            "trace=read,exit,exit_group",
        ]
        tracer = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
        stderr_prefix = wait_for_debug_ready(tracer)
        ready_events = parse_ready_events(stderr_prefix)
        if not ready_events or ready_events[-1].get("target_pid") != target.pid:
            raise RuntimeError(f"attach tracer readiness target mismatch: {stderr_prefix!r}")
        os.kill(target.pid, signal.SIGUSR1)
        target_stdout, target_stderr = target.communicate(timeout=10)
        tracer_stdout, tracer_stderr = tracer.communicate(timeout=30)
        tracer_stderr = stderr_prefix + tracer_stderr
        result = subprocess.CompletedProcess(
            command, tracer.returncode, tracer_stdout, tracer_stderr
        )
        return AttachCapture(
            target.returncode,
            target_stdout,
            target_stderr,
            result,
            parse_stats_events(tracer_stderr),
        )
    finally:
        stop_process(target)
        stop_process(tracer)


def collect_attach_thread_events(fixture):
    target = subprocess.Popen(
        [fixture],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    tracer = None
    try:
        ready = target.stdout.readline().strip()
        fields = ready.split()
        if len(fields) != 2 or fields[0] != "attach-thread-ready":
            raise RuntimeError(f"attach thread fixture did not become ready: {ready!r}")
        attach_tid = int(fields[1])
        command = [
            STRACE_WRAPPER,
            "--debug-events",
            "-p",
            str(attach_tid),
            "-e",
            "trace=getpid,exit,exit_group",
        ]
        tracer = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
        stderr_prefix = wait_for_debug_ready(tracer)
        ready_events = parse_ready_events(stderr_prefix)
        if not ready_events or ready_events[-1].get("target_pid") != attach_tid:
            raise RuntimeError(
                f"attach thread tracer readiness mismatch: {stderr_prefix!r}"
            )
        os.kill(target.pid, signal.SIGUSR1)
        target_stdout, target_stderr = target.communicate(timeout=10)
        tracer_stdout, tracer_stderr = tracer.communicate(timeout=30)
        tracer_stderr = stderr_prefix + tracer_stderr
        result = subprocess.CompletedProcess(
            command, tracer.returncode, tracer_stdout, tracer_stderr
        )
        return AttachThreadCapture(
            target.returncode,
            target_stdout,
            target_stderr,
            attach_tid,
            result,
            parse_json_events(tracer_stderr),
            parse_stats_events(tracer_stderr),
        )
    finally:
        stop_process(target)
        stop_process(tracer)


def collect_semantic_context(fixture):
    fcntl_source = os.path.join(SCRIPT_DIR, "fixtures", "ebpf_fcntl_fixture.c")
    fcntl_fixture = build_named_fixture("strace-go-ebpf-fcntl-fixture", (fcntl_source,))
    thread_fixture = build_ebpf_thread_fixture()
    attach_fixture = build_ebpf_attach_fixture()
    attach_thread_fixture = build_ebpf_attach_thread_fixture()
    mount_query_fixture = build_ebpf_mount_query_fixture()
    mount_path_fixture = build_ebpf_mount_path_fixture()
    dirent_fixture = build_ebpf_dirent_fixture()
    mmsg_fixture = build_ebpf_mmsg_fixture()
    return SemanticContext(
        main=collect_semantic_events(fixture),
        fcntl=event_capture(run_strace_go_json(["-e", "trace=fcntl", fcntl_fixture])),
        dirent=collect_dirent_events(dirent_fixture),
        mmsg=collect_mmsg_events(mmsg_fixture),
        mount_query=collect_mount_query_events(mount_query_fixture),
        mount_path=collect_mount_path_events(mount_path_fixture),
        mount_path_filtered=collect_mount_path_events(
            mount_path_fixture, "/dev/full"
        ),
        thread=collect_thread_lifecycle_events(thread_fixture),
        thread_text=collect_thread_unfinished_text(thread_fixture),
        attach=collect_attach_orphan_stats(attach_fixture),
        attach_thread=collect_attach_thread_events(attach_thread_fixture),
    )


def check_write_only_filter(fixture, failures):
    result = run_strace_go_json(["-e", "trace=write", fixture], debug=True)
    events = parse_json_events(result.stderr)
    stats_events = parse_stats_events(result.stderr)
    require(result.returncode == 0, failures, f"filter fixture rc={result.returncode}")
    require(events, failures, "write-only filter produced no events")
    require(
        all(event.get("syscall") == "write" for event in events),
        failures,
        f"write-only filter leaked events: {sorted({event.get('syscall') for event in events})}",
    )
    require(
        len(stats_events) == 1 and valid_stats_event(stats_events[0]),
        failures,
        "write-only filter stats event missing",
    )
    return len(events)


def finish_semantic(context, failures, filter_event_count):
    print_semantic_summary(context, filter_event_count)
    if not failures:
        print("PASS: ebpf-semantic")
        return 0
    print("\n=== EBPF SEMANTIC FAILURES ===")
    for failure in failures:
        print(f"FAIL: {failure}")
    print("\n--- stderr tail ---")
    print("\n".join(context.main.result.stderr.splitlines()[-40:]))
    return 1


def run_ebpf_semantic(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_ebpf_fixture()
    context = collect_semantic_context(fixture)
    failures = []
    check_semantic_context(context, failures)
    failures.extend(run_epoll_semantic(STRACE_WRAPPER))
    failures.extend(run_cloexec_semantic())
    failures.extend(run_signalfd_semantic(STRACE_WRAPPER, PROJECT_ROOT))
    failures.extend(run_sockopt_semantic(STRACE_WRAPPER, PROJECT_ROOT))
    filter_event_count = check_write_only_filter(fixture, failures)
    return finish_semantic(context, failures, filter_event_count)
