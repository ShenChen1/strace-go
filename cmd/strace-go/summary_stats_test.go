package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryStatsRecordsAndPrintsSortedSyscalls(t *testing.T) {
	stats := newSummaryStats()
	stats.Record("read", 1000, 4)
	stats.Record("write", 3000, -2)
	stats.Record("read", 1000, 0)

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
