#!/usr/bin/env python3
import os
import glob
import subprocess
import sys

tests_dir = "/opt/strace-go/strace-upstream/tests"
strace_wrapper = "/opt/strace-go/test/strace-sudo.sh"

# 57 small batch tests
ignored_tests = {
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
}

# 5 diagnostic tests
ignored_tests.update([
    "execveat.gen.test", "recvfrom.gen.test", "fcntl.gen.test", "ioctl.test", "getgid.gen.test"
])

os.environ["STRACE"] = strace_wrapper
os.environ["SIZEOF_LONG"] = "8"
os.environ["STRACE_ARCH"] = "x86_64"
os.environ["STRACE_NATIVE_ARCH"] = "x86_64"

# Find all *.gen.test in tests_dir
all_tests = [os.path.basename(p) for p in glob.glob(os.path.join(tests_dir, "*.gen.test"))]
all_tests = sorted(list(set(all_tests) - ignored_tests))

# We can limit the number of tests to run
limit = 40
if len(sys.argv) > 1:
    try:
        limit = int(sys.argv[1])
    except ValueError:
        pass

print(f"Found {len(all_tests)} other generated tests. Running up to {limit} of them...")

passed = 0
failed = 0
failed_list = []

for t in all_tests[:limit]:
    # Ensure binary is made
    bin_name = t.replace(".test", "").replace(".gen", "")
    subprocess.run(["make", bin_name], cwd=tests_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"Running {t}... ", end="", flush=True)
    res = subprocess.run([f"./{t}"], cwd=tests_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode == 0:
        print("PASS")
        passed += 1
    else:
        print("FAIL")
        failed += 1
        failed_list.append(t)
        # Try to print some diff
        stdout_str = res.stdout.decode("utf-8", errors="ignore")
        stderr_str = res.stderr.decode("utf-8", errors="ignore")
        print(f"--- FAIL DETAILS FOR {t} ---")
        if stdout_str:
            print("STDOUT:")
            print("\n".join(stdout_str.split("\n")[:15]))
        if stderr_str:
            print("STDERR:")
            print(stderr_str)
        print("----------------------------")

print(f"\nSummary: {passed} passed, {failed} failed.")
if failed_list:
    print(f"Failed tests: {failed_list}")
