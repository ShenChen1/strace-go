import subprocess
import re
import sys
import os

def normalize(line):
    # Remove PID
    line = re.sub(r'^\d+\s+', '', line)
    # Remove hex addresses
    line = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
    # Remove timing info
    line = re.sub(r' <[0-9.]+>$', '', line)
    # Remove pointer values in structures if they vary
    # Remove some varying flags or return values
    return line.strip()

def run_test(cmd):
    print(f"Running test: {' '.join(cmd)}")
    
    # Run original strace
    strace_cmd = ["sudo", "strace", "-q"] + cmd
    try:
        strace_out = subprocess.check_output(strace_cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        strace_out = e.output.decode('utf-8', errors='ignore')
    
    # Run strace-go
    go_cmd = ["sudo", "/opt/strace-go/strace-go"] + cmd
    try:
        go_out = subprocess.check_output(go_cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        go_out = e.output.decode('utf-8', errors='ignore')

    strace_lines = [normalize(l) for l in strace_out.splitlines() if '(' in l]
    go_lines = [normalize(l) for l in go_out.splitlines() if '(' in l]
    
    diff = 0
    common_syscalls = ["openat", "read", "write", "close", "fstat", "mmap", "munmap", "brk", "rt_sigprocmask", "getdents64"]
    
    for sc in common_syscalls:
        s_count = sum(1 for l in strace_lines if l.startswith(sc))
        g_count = sum(1 for l in go_lines if l.startswith(sc))
        print(f"  {sc:15}: strace={s_count:3}, strace-go={g_count:3} {'[OK]' if g_count >= s_count else '[FAIL]'}")
        if g_count < s_count: diff += 1
    
    return diff == 0

if __name__ == "__main__":
    os.chdir("/opt/strace-go")
    tests = [
        ["ls", "/tmp"],
        ["python3", "-c", "import time; time.sleep(0.01)"],
        ["cat", "/etc/passwd"]
    ]
    
    all_ok = True
    for t in tests:
        if not run_test(t):
            all_ok = False
            
    if all_ok:
        print("\nALL REGRESSION TESTS PASSED")
        sys.exit(0)
    else:
        print("\nREGRESSION TESTS FAILED")
        sys.exit(1)
