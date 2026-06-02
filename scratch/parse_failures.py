import re
import sys
from collections import defaultdict

log_file = sys.argv[1]

# Parsing states
current_test = None
current_diff = []
tests = {}

with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

for line in lines:
    if line.startswith("--- ") and line.endswith(".test ---\n"):
        if current_test and current_diff:
            tests[current_test] = current_diff
        current_test = line[4:-10]
        current_diff = []
    elif current_test:
        current_diff.append(line)

if current_test and current_diff:
    tests[current_test] = current_diff

categories = defaultdict(list)

for test, diff in tests.items():
    diff_str = "".join(diff)
    if "/* 16 vars */" in diff_str and "/* 15 vars */" in diff_str:
        categories["Execve Vars Count Mismatch (16 vs 15)"].append(test)
    elif "PRIO_PROCESS" in diff_str or "PRIO_PGRP" in diff_str or "getpriority(0" in diff_str:
        categories["Priority Macros (getpriority/setpriority)"].append(test)
    elif "ITIMER_REAL" in diff_str:
        categories["ITIMER Macros (setitimer/getitimer)"].append(test)
    elif "tz_minuteswest" in diff_str:
        categories["Timeofday struct parsing"].append(test)
    elif "EFAULT (Bad address)" in diff_str:
        categories["EFAULT Handling"].append(test)
    elif "EAGAIN" in diff_str or "EINVAL" in diff_str or "ENOENT" in diff_str:
        categories["Error Code / Name Mismatch"].append(test)
    elif "O_RDONLY" in diff_str or "O_WRONLY" in diff_str:
        categories["File Open Flags (O_*) Mismatch"].append(test)
    elif "AT_FDCWD" in diff_str:
        categories["AT_FDCWD Handling"].append(test)
    elif "SIG" in diff_str and "sa_mask" in diff_str:
        categories["Signal / Sigaction Parsing"].append(test)
    elif "epoll" in diff_str:
        categories["Epoll Events/Data Parsing"].append(test)
    elif "st_mode=" in diff_str or "st_size=" in diff_str:
        categories["Stat Struct Parsing"].append(test)
    else:
        categories["Other"].append(test)

for cat, ts in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"[{len(ts)}] {cat}")
    for t in ts[:5]:
        print(f"  - {t}")
    if len(ts) > 5:
        print(f"  ... and {len(ts)-5} more")
    print()
