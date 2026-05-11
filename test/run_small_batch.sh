#!/bin/bash
export STRACE=/opt/strace-go/test/strace-sudo.sh
export SIZEOF_LONG=8
cd ../strace-upstream || exit 1
if [ ! -f Makefile ]; then
    ./bootstrap
    ./configure --enable-mpers=no --disable-werror
fi
make -j$(nproc) >/dev/null 2>&1
cd tests || exit 1
passed=0
failed=0
total=0

# List of tests to run (a small representative sample)
tests="getpid.gen.test access.gen.test chmod.gen.test openat.gen.test brk.test stat.gen.test fstat.gen.test lstat.gen.test rename.gen.test mkdir.gen.test"

for t in $tests; do
    bin_name=${t%.test}
    bin_name=${bin_name%.gen}
    make $bin_name >/dev/null 2>&1

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
