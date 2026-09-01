package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryStatsRecordsAndPrintsSortedSyscalls(t *testing.T) {
	stats := newSummaryStats()
	stats.Record("read", 1000, 1000, 4)
	stats.Record("write", 3000, 3000, -2)
	stats.Record("read", 1000, 1000, 0)

	var output bytes.Buffer
	stats.Print(&output)
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("summary lines = %d, want header, separators, two syscalls, total; output:\n%s", len(lines), output.String())
	}
	if !strings.HasSuffix(lines[2], "write") {
		t.Fatalf("first syscall line = %q, want write sorted by duration", lines[2])
	}
	if !strings.Contains(lines[2], "         1         1 write") {
		t.Fatalf("write line = %q, want one call and one error", lines[2])
	}
	if !strings.HasSuffix(lines[3], "read") {
		t.Fatalf("second syscall line = %q, want read", lines[3])
	}
	if !strings.Contains(lines[5], "        3         1 total") {
		t.Fatalf("total line = %q, want three calls and one error", lines[5])
	}
}

func TestSummaryStatsSeparatesCPUAndWallClockTime(t *testing.T) {
	stats := newSummaryStats()
	stats.Record("nanosleep", 2_000_000, 1_000_000_000, 0)

	entry := stats.stats["nanosleep"]
	if entry.cpu.total != 2_000_000 || entry.wall.total != 1_000_000_000 {
		t.Fatalf("summary timing = %+v, want 2ms CPU and 1s wall", entry)
	}

	var output bytes.Buffer
	stats.Print(&output)
	if !strings.Contains(output.String(), "0.002000") || strings.Contains(output.String(), "1.000000") {
		t.Fatalf("default summary must render CPU time:\n%s", output.String())
	}
}
