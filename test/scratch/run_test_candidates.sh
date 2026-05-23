#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export STRACE="$DIR/../strace-sudo.sh"
export SIZEOF_LONG=8

cd "$DIR/../../strace-upstream/tests" || exit 1

candidates="kill.gen.test dup.gen.test dup2.gen.test dup3.gen.test pipe.gen.test pipe2.gen.test eventfd.gen.test eventfd2.gen.test prlimit64.gen.test getrlimit.gen.test setrlimit.gen.test nanosleep.gen.test umask.gen.test mkdirat.gen.test rmdir.gen.test ftruncate.gen.test truncate.gen.test"

for t in $candidates; do
    if [ -f "$t" ]; then
        bin_name=${t%.test}
        bin_name=${bin_name%.gen}
        make $bin_name >/dev/null 2>&1
        echo -n "Candidate $t: "
        if ./$t >/dev/null 2>&1; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    else
        echo "Candidate $t: NOT FOUND"
    fi
done
