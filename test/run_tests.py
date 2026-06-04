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

SMOKE_TESTS = [
    "chdir.gen.test",
    "open.gen.test",
    "openat.gen.test",
    "read.gen.test",
    "write.gen.test",
    
    "stat.gen.test",
    "mmap.test"
]

# Tests for the next feature we are tackling
# Add tests here when working on a new syscall or feature
MORE_TESTS = [
    # "accept.gen.test",
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

def get_tests(suite):
    valid_tests = []
    if not os.path.exists(TESTS_DIR):
        print(f"Tests dir {TESTS_DIR} not found.")
        return []
    
    for f in os.listdir(TESTS_DIR):
        if f.endswith(".test") and not f.endswith(".sh"):
            # Exclude tests that need special handling or are known to freeze
            if f in ["strace-k.test", "strace-E.test"]:
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
    
    if not args.skip_build:
        build_upstream()
        
    tests_to_run = get_tests(args.suite)
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
