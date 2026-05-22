#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export STRACE="$DIR/strace-sudo.sh"
export SIZEOF_LONG=8
cd "$DIR/../strace-upstream" || exit 1
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
tests="getpid.gen.test access.gen.test chmod.gen.test openat.gen.test brk.test stat.gen.test fstat.gen.test lstat.gen.test rename.gen.test mkdir.gen.test add_key.gen.test request_key.gen.test link.gen.test symlink.gen.test symlinkat.gen.test readlink.gen.test readlinkat.gen.test unlinkat.gen.test chown.gen.test fchown.gen.test lchown.gen.test fchownat.gen.test utimensat.gen.test mknodat.gen.test mknod.gen.test"

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
