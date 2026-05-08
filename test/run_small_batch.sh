#!/bin/bash
export STRACE=/opt/strace-go/test/strace-sudo.sh
export SIZEOF_LONG=8
cd ../strace-upstream/tests || exit 1
passed=0
failed=0
total=0

# List of tests to run (a small representative sample)
tests="getpid.gen.test access.gen.test chmod.gen.test openat.gen.test brk.test stat.gen.test fstat.gen.test lstat.gen.test rename.test mkdir.test"

for t in $tests; do
    total=$((total+1))
    echo -n "Running $t... "
    if ./$t >/dev/null 2>&1; then
        echo "PASS"
        passed=$((passed+1))
    else
        echo "FAIL"
        failed=$((failed+1))
    fi
done

echo "Summary: $passed passed, $failed failed, $total total"
