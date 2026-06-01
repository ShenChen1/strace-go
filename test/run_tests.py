#!/usr/bin/env python3
import os
import glob
import subprocess
import sys
import argparse
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed

TESTS_DIR = "/opt/strace-go/strace-upstream/tests"
UPSTREAM_DIR = "/opt/strace-go/strace-upstream"
STRACE_WRAPPER = "/opt/strace-go/test/strace-sudo.sh"

SMALL_BATCH_TESTS = [
    "getpid.gen.test", "access.gen.test", "chmod.gen.test", "openat.gen.test", "brk.test",
    "stat.gen.test", "fstat.gen.test", "lstat.gen.test", "rename.gen.test", "mkdir.gen.test",
    "add_key.gen.test", "request_key.gen.test", "link.gen.test", "symlink.gen.test",
    "symlinkat.gen.test", "readlink.gen.test", "readlinkat.gen.test", "unlinkat.gen.test",
    "chown.gen.test", "fchown.gen.test", "lchown.gen.test", "fchownat.gen.test",
    "utimensat.gen.test", "mknodat.gen.test", "mknod.gen.test", "mlock.gen.test",
    "mlock2.gen.test", "mlockall.gen.test", "mmap.test", "dup.gen.test", "dup2.gen.test",
    "dup3.gen.test", "mkdirat.gen.test", "rmdir.gen.test", "umask.gen.test", "kill.gen.test",
    "pipe2.gen.test", "getrlimit.gen.test", "setrlimit.gen.test", "prlimit64.gen.test",
    "nanosleep.gen.test", "truncate.gen.test", "ftruncate.gen.test", "clone_parent.gen.test",
    "clone_parent-q.gen.test", "clone_parent-qq.gen.test", "clone_parent--quiet-exit.gen.test",
    "newfstatat.gen.test", "sysinfo.gen.test", "statfs.gen.test", "fstatfs.gen.test",
    "epoll_ctl.gen.test", "threads-execve.test", "threads-execve-q.gen.test",
    "threads-execve-qq.gen.test", "threads-execve-qqq.gen.test",
    "threads-execve--quiet-thread-execve.gen.test"
]

DIAGNOSTIC_TESTS = [
    "execveat.gen.test", "recvfrom.gen.test", "fcntl.gen.test", "ioctl.test", "getgid.gen.test"
]

def parse_args():
    parser = argparse.ArgumentParser(description="Unified test framework for strace-go")
    parser.add_argument("--suite", choices=["small", "more", "all"], default="small",
                        help="Which test suite to run (small=core, more=filtered comprehensive, all=everything)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit the number of tests to run (0 for unlimited)")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Number of parallel workers (default 1)")
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

def get_tests(suite):
    if suite == "small":
        return SMALL_BATCH_TESTS
        
    all_tests = []
    for p in glob.glob(os.path.join(TESTS_DIR, "*.gen.test")):
        all_tests.append(os.path.basename(p))
    
    # Include non-gen tests that are part of SMALL_BATCH_TESTS if they exist
    for t in SMALL_BATCH_TESTS:
        if t.endswith(".test") and not t.endswith(".gen.test"):
            if os.path.exists(os.path.join(TESTS_DIR, t)):
                all_tests.append(t)
                
    all_tests = sorted(list(set(all_tests)))

    if suite == "all":
        return all_tests
        
    # suite == "more"
    ignored = set(SMALL_BATCH_TESTS) | set(DIAGNOSTIC_TESTS)
    filtered_tests = []
    for t in all_tests:
        if t in ignored:
            continue
        if any(k in t for k in ["success", "inject", "fault", "secontext", "_newselect"]):
            continue
        filtered_tests.append(t)
    return filtered_tests

def run_test(t):
    bin_name = t.replace(".test", "").replace(".gen", "")
    subprocess.run(["make", bin_name], cwd=TESTS_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    res = subprocess.run([f"./{t}"], cwd=TESTS_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {
        "test": t,
        "success": res.returncode == 0,
        "stdout": res.stdout.decode("utf-8", errors="ignore"),
        "stderr": res.stderr.decode("utf-8", errors="ignore"),
        "rc": res.returncode
    }

def main():
    args = parse_args()
    setup_env()
    
    if not args.skip_build:
        build_upstream()
        
    tests_to_run = get_tests(args.suite)
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
