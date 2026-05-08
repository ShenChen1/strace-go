#!/bin/bash
export STRACE=/opt/strace-go/test/strace-sudo.sh
export SIZEOF_LONG=8
cd ../strace-upstream/tests || exit 1
passed=0
failed=0
total=0

# List of tests to run (first 50 for quick check)
tests=$(ls *.gen.test | head -n 50)

for t in $tests; do
    total=$((total+1))
    if ./$t >/dev/null 2>&1; then
        echo "PASS: $t"
        passed=$((passed+1))
    else
        echo "FAIL: $t"
        failed=$((failed+1))
    fi
done

echo "Summary: $passed passed, $failed failed, $total total"
