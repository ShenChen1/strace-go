#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export STRACE="$DIR/strace-sudo.sh"
export SIZEOF_LONG=8
cd ../strace-upstream || exit 1
if [ ! -f Makefile ]; then
    ./bootstrap
    ./configure --enable-mpers=no CFLAGS="-g -O2 -Wno-error"
fi
make -j$(nproc) >/dev/null 2>&1
cd tests || exit 1
passed=0
failed=0
total=0

# List of tests to run
tests=$(ls *.gen.test)

for t in $tests; do
    bin_name=${t%.test}
    bin_name=${bin_name%.gen}
    make $bin_name >/dev/null 2>&1

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
