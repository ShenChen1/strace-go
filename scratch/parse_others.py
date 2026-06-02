import sys

log_file = sys.argv[1]

tests = {}
current_test = None
current_diff = []
with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        if line.startswith("--- ") and line.endswith(".test ---\n"):
            if current_test and current_diff:
                tests[current_test] = current_diff
            current_test = line[4:-10]
            current_diff = []
        elif current_test:
            current_diff.append(line)
if current_test and current_diff:
    tests[current_test] = current_diff

count = 0
for test in ["btrfs.gen", "clock.gen", "clone3-report-ns-id.gen", "aio.gen", "aio_pgetevents.gen", "bpf-success.gen", "epoll_pwait2-P.gen", "dev--decode-fds-all.gen"]:
    if test in tests:
        print(f"[{test}]")
        print("".join(tests[test][:20]))
        print("-" * 40)
