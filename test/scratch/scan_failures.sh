#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export STRACE="$DIR/../strace-sudo.sh"
export SIZEOF_LONG=8

cd "$DIR/../../strace-upstream/tests" || exit 1

# 清理现有的临时结果
rm -f /tmp/scan_passed.log /tmp/scan_failed.log /tmp/scan_skipped.log

run_one() {
    local t=$1
    if ./$t >/dev/null 2>&1; then
        echo "$t" >> /tmp/scan_passed.log
    else
        local rc=$?
        if [ $rc -eq 77 ]; then
            echo "$t" >> /tmp/scan_skipped.log
        else
            echo "$t (rc=$rc)" >> /tmp/scan_failed.log
            # 同时将失败的简要信息打印到终端以便实时观察
            echo "FAIL: $t"
        fi
    fi
}
export -f run_one

echo "Starting scan of *.gen.test..."
# 并行度设为 16
ls *.gen.test | xargs -I {} -P 16 bash -c 'run_one "$@"' _ {}

# 汇总结果
passed_cnt=$(wc -l < /tmp/scan_passed.log 2>/dev/null || echo 0)
failed_cnt=$(wc -l < /tmp/scan_failed.log 2>/dev/null || echo 0)
skipped_cnt=$(wc -l < /tmp/scan_skipped.log 2>/dev/null || echo 0)
total_cnt=$((passed_cnt + failed_cnt + skipped_cnt))

echo "=== SCAN SUMMARY ==="
echo "Passed:  $passed_cnt"
echo "Failed:  $failed_cnt"
echo "Skipped: $skipped_cnt"
echo "Total:   $total_cnt"
