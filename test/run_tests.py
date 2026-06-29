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
from concurrent.futures import ThreadPoolExecutor, as_completed

TESTS_DIR = "/opt/strace-go/strace-upstream/tests"
UPSTREAM_DIR = "/opt/strace-go/strace-upstream"
STRACE_WRAPPER = "/opt/strace-go/test/strace-sudo.sh"
STRACE_GO_BIN = "/opt/strace-go/strace-go"
FIXTURE_SRC = "/opt/strace-go/test/fixtures/ebpf_semantic_fixture.c"

SMOKE_TESTS = [
    "accept.gen.test",
    "accept4.gen.test",
    "access.gen.test",
    "acct.gen.test",
    "add_key.gen.test",
    "adjtimex.gen.test",
    "alarm.gen.test",
    "brk.test",
    "chdir.gen.test",
    "chmod.gen.test",
    "chown.gen.test",
    "rename.gen.test",
    "clock_adjtime.gen.test",
    "creat.gen.test",
    "fstat.gen.test",
    "lstat.gen.test",
    "mmap.test",
    "open.gen.test",
    "openat.gen.test",
    "read.gen.test",
    "stat.gen.test",
    "statfs.gen.test",
    "symlinkat.gen.test",
    "sync.gen.test",
    "write.gen.test"
]

# Tests for the next feature we are tackling
# Add tests here when working on a new syscall or feature
MORE_TESTS = [
    "strace-A.test",
    "strace-p.test",
    "strace-C.test",
    "strace-e-negation.test",
    "strace-e-class.test",
    "strace-e-class2.test",
    "strace-E.test",
    "strace-x.gen.test",
    "strace-xx.gen.test",
    "aio_pgetevents.gen.test",
    "aio.gen.test",
    "arch_prctl-Xabbrev.gen.test",
    "arch_prctl-Xverbose.gen.test",
    "arch_prctl-success-Xabbrev.gen.test",
    "arch_prctl-success-Xraw.gen.test",
    "arch_prctl-success-Xverbose.gen.test",
    "arch_prctl-success.gen.test",
    "arch_prctl.gen.test",
    "at_fdcwd-pathmax.gen.test",
    "bpf-v.gen.test",
    "bpf.gen.test",
    "cachestat-P.gen.test",
    "cachestat.gen.test",
    "chroot.gen.test",
    "clock_xettime.gen.test",
    "clone_parent--quiet-exit.gen.test",
    "clone_parent-qq.gen.test",
    "clone_parent.gen.test",
    
    "dup-P.gen.test",
    "dup2-P.gen.test",
    "dup3-P.gen.test",
    "dup-yy.gen.test",
    "dup2.gen.test",
    "dup3.gen.test",
    "epoll_create.gen.test",
    "epoll_create1.gen.test",
    "epoll_ctl.gen.test",
    "epoll_pwait2-y.gen.test",
    "epoll_pwait2.gen.test",
    "epoll_wait.gen.test",
    "erestartsys.gen.test",
    "eventfd.test",
    "fchmod.gen.test",
    "fchmodat.gen.test",
    "fchown.gen.test",
    "fchownat.gen.test",
    "fcntl.gen.test",
    "filter-unavailable.test",
    "filter_seccomp-flag.gen.test",
    "fspick.gen.test",
    "fstat-Xabbrev.gen.test",
    "fstatfs.gen.test",
    "ftruncate.gen.test",
    "getcwd.gen.test",
    "getegid.gen.test",
    "geteuid.gen.test",
    "getgid.gen.test",
    "getpgrp.gen.test",
    "getpid.gen.test",
    "getppid.gen.test",
    "getrlimit.gen.test",
    "getsid.gen.test",
    "getsockname.gen.test",
    "gettid.gen.test",
    "getuid.test",
    "inotify_init.gen.test",
    "ioctl.test",
    "ioctl_fiemap-Xabbrev.gen.test",
    "ioctl_fiemap-Xraw.gen.test",
    "ioctl_fiemap-Xverbose.gen.test",
    "ioctl_fiemap.gen.test",
    "ioctl_fs_0x15-Xabbrev.gen.test",
    "ioctl_fs_0x15.gen.test",
    "arch_prctl-Xraw.gen.test",
    "status-successful.gen.test",
    "status-failed.gen.test",
    "status-all.gen.test",
    "status-none.gen.test",
    "fork-f.gen.test",
    "vfork-f.gen.test",
    "strace-E.test",
    "strace-E-override.test",
    "strace-E-unset.test",
    "attach-p-cmd.test",
    "attach-f-p.test",
    "strace-r.test",
    "strace-t.test",
    "strace-tt.test",
    "strace-ttt.test",
    "strace-T_upper.test",
    "strace-x.gen.test",
    "strace-xx.gen.test",
    "read-write.gen.test",
    "pread64-pwrite64.gen.test",
    "opipe.test",
]

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
    env.setdefault("GOCACHE", "/tmp/strace-go-gocache")
    subprocess.run(["go", "build", "-o", STRACE_GO_BIN, "./cmd/strace-go"], cwd="/opt/strace-go", env=env, check=True)

def build_ebpf_fixture():
    out = os.path.join(tempfile.gettempdir(), "strace-go-ebpf-semantic-fixture")
    subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-o", out, FIXTURE_SRC], check=True)
    os.chmod(out, 0o755)
    return out

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

def run_strace_go_json(args, timeout=30, debug=False):
    event_flag = "--debug-events" if debug else "--event-format=json"
    cmd = [STRACE_WRAPPER, event_flag] + args
    env = os.environ.copy()
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          errors="ignore", timeout=timeout, env=env)

def require(condition, failures, message):
    if not condition:
        failures.append(message)

def run_ebpf_semantic(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_ebpf_fixture()

    failures = []

    trace_set = "open,openat,read,write,close,execve,exit,exit_group"
    res = run_strace_go_json(["-f", "-e", f"trace={trace_set}", fixture])
    events = parse_json_events(res.stderr)
    lifecycle_events = parse_lifecycle_events(res.stderr)
    names = {ev.get("syscall") for ev in events}
    lifecycle_actions = {ev.get("action") for ev in lifecycle_events}
    enter_events = [ev for ev in events if ev.get("event_type") == "enter"]
    exit_events = [ev for ev in events if ev.get("event_type") == "exit"]

    require(res.returncode == 0, failures, f"semantic fixture rc={res.returncode}")
    require("ebpf-fixture-write" in res.stdout, failures, "fixture stdout marker missing")
    require(len(events) > 0, failures, "no JSON syscall events decoded")
    require(len(enter_events) > 0, failures, "no syscall enter JSON events decoded")
    require(len(exit_events) > 0, failures, "no syscall exit JSON events decoded")
    require("write" in names, failures, "write event missing")
    require(("openat" in names) or ("open" in names), failures, "open/openat event missing")
    require("read" in names, failures, "read event missing")
    require("close" in names, failures, "close event missing")
    require("execve" in names, failures, "child execve event missing; fork following may be broken")
    require(any(ev.get("syscall") == "write" for ev in enter_events), failures, "write enter event missing")
    require(any(ev.get("syscall") == "write" for ev in exit_events), failures, "write exit event missing")
    require(any(ev.get("syscall") == "read" for ev in enter_events), failures, "read enter event missing")
    require(any(ev.get("syscall") == "read" for ev in exit_events), failures, "read exit event missing")
    require(any(ev.get("syscall") == "write" and ev.get("paired_enter") for ev in exit_events),
            failures, "write exit event was not paired with enter state")
    require(any(ev.get("syscall") == "read" and ev.get("paired_enter") for ev in exit_events),
            failures, "read exit event was not paired with enter state")
    require(any(ev.get("failed") and ev.get("errno") == 2 for ev in events), failures, "ENOENT failed-open event missing")
    require(any(ev.get("syscall") == "write" and "ebpf-fixture-write" in " ".join(ev.get("arg_text") or []) for ev in events),
            failures, "write payload text missing from JSON arg_text")
    require(len({ev.get("pid") for ev in events}) >= 2, failures, "forked child pid events missing")
    require("fork" in lifecycle_actions, failures, "fork lifecycle event missing")
    require("exec" in lifecycle_actions, failures, "exec lifecycle event missing")
    require(("exit" in lifecycle_actions) or ("free" in lifecycle_actions), failures, "exit/free lifecycle event missing")
    filter_res = run_strace_go_json(["-e", "trace=write", fixture], debug=True)
    filter_events = parse_json_events(filter_res.stderr)
    require(filter_res.returncode == 0, failures, f"filter fixture rc={filter_res.returncode}")
    require(len(filter_events) > 0, failures, "write-only filter produced no events")
    require(all(ev.get("syscall") == "write" for ev in filter_events),
            failures, f"write-only filter leaked events: {sorted({ev.get('syscall') for ev in filter_events})}")

    print(f"=> eBPF semantic events: {len(events)}")
    print(f"=> eBPF semantic enter/exit: {len(enter_events)}/{len(exit_events)}")
    print(f"=> eBPF lifecycle events: {len(lifecycle_events)}")
    print(f"=> eBPF write-only events: {len(filter_events)}")
    if failures:
        print("\n=== EBPF SEMANTIC FAILURES ===")
        for failure in failures:
            print(f"FAIL: {failure}")
        print("\n--- stderr tail ---")
        print("\n".join(res.stderr.splitlines()[-40:]))
        return 1
    print("PASS: ebpf-semantic")
    return 0

def run_ebpf_perf(args):
    if not args.skip_build:
        build_strace_go()
    fixture = build_ebpf_fixture()

    start = time.monotonic()
    res = run_strace_go_json(["-e", "trace=getpid", fixture, "perf"], timeout=60)
    elapsed = time.monotonic() - start
    events = parse_json_events(res.stderr)
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
    if elapsed > 0:
        print(f"events_per_sec: {len(getpid_exit_events) / elapsed:.2f}")

    if res.returncode != 0 or len(getpid_exit_events) < 1000 or len(getpid_enter_events) < 1000 or not all(ev.get("paired_enter") for ev in getpid_exit_events):
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
    elif suite == "all":
        return valid_tests
    else:
        # Fallback to single test matching
        return [t for t in valid_tests if suite in t]


def run_test(t):
    bin_name = t.replace(".test", "").replace(".gen", "")
    subprocess.run(["make", bin_name], cwd=TESTS_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    import tempfile
    out_fd, out_path = tempfile.mkstemp()
    err_fd, err_path = tempfile.mkstemp()
    
    try:
        with os.fdopen(out_fd, 'w') as out_f, os.fdopen(err_fd, 'w') as err_f:
            try:
                res = subprocess.run([f"./{t}"], cwd=TESTS_DIR, stdin=subprocess.DEVNULL, stdout=out_f, stderr=err_f, timeout=30)
                rc = res.returncode
            except subprocess.TimeoutExpired:
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

def main():
    args = parse_args()
    setup_env()

    if args.suite == "ebpf-semantic":
        sys.exit(run_ebpf_semantic(args))
    if args.suite == "ebpf-perf":
        sys.exit(run_ebpf_perf(args))
    
    upstream_suite = args.suite
    if upstream_suite == "upstream-reference":
        upstream_suite = "small"

    if not args.skip_build:
        build_upstream()
        
    tests_to_run = get_tests(upstream_suite)
    if args.filter:
        final_list = [t for t in tests_to_run if t == args.filter]
        tests_to_run = final_list
    if args.limit > 0:
        tests_to_run = tests_to_run[:args.limit]
        
    print(f"=> Running {len(tests_to_run)} tests from '{args.suite}' suite...")
    
    passed = 0
    failed = 0
    skipped = 0
    failed_list = []
    
    if args.parallel > 1:
        print(f"=> Using {args.parallel} parallel workers.")
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {executor.submit(run_test, t): t for t in tests_to_run}
            for future in as_completed(futures):
                result = future.result()
                t = result["test"]
                if result["success"]:
                    print(f"PASS: {t}")
                    passed += 1
                else:
                    if result["rc"] == 77:
                        print(f"SKIP: {t}")
                        skipped += 1
                        continue
                    print(f"FAIL: {t}")
                    failed += 1
                    failed_list.append(result)
    else:
        for t in tests_to_run:
            print(f"Running {t}... ", end="", flush=True)
            result = run_test(t)
            if result["success"]:
                print("PASS")
                passed += 1
            else:
                if result["rc"] == 77:
                    print("SKIP")
                    skipped += 1
                    continue
                print("FAIL")
                failed += 1
                failed_list.append(result)
                
    print("\n=== SUMMARY ===")
    print(f"Passed:  {passed}")
    print(f"Failed:  {failed}")
    print(f"Skipped: {skipped}")
    print(f"Total:   {passed + failed + skipped}")
    
    if failed_list:
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

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
