package main

import (
	"strings"
	"testing"
)

func TestSumBPFStatsValuesAggregatesAllCounters(t *testing.T) {
	values := []bpfBpfStats{
		{RingbufReserveFail: 1, RingbufCopyFail: 2, PayloadTruncatedEvents: 3, PendingUpdateFail: 4, OrphanExit: 5, PendingMismatch: 6, LifecycleMapUpdateFail: 7},
		{RingbufReserveFail: 10, RingbufCopyFail: 20, PayloadTruncatedEvents: 30, PendingUpdateFail: 40, OrphanExit: 50, PendingMismatch: 60, LifecycleMapUpdateFail: 70},
	}
	stats := sumBPFStatsValues(values)
	if !stats.Available || stats.Error != "" {
		t.Fatalf("sum stats = %+v, want available without error", stats)
	}
	if stats.RingbufReserveFail != 11 || stats.RingbufCopyFail != 22 ||
		stats.PayloadTruncatedEvents != 33 || stats.PendingUpdateFail != 44 || stats.OrphanExit != 55 || stats.PendingMismatch != 66 || stats.LifecycleMapUpdateFail != 77 {
		t.Fatalf("sum stats = %+v, want 11/22/33/44/55/66/77", stats)
	}
}

func TestSumBPFStatsValuesEmptyReturnsAvailableZero(t *testing.T) {
	stats := sumBPFStatsValues(nil)
	if !stats.Available || stats.RingbufReserveFail != 0 || stats.PendingUpdateFail != 0 || stats.OrphanExit != 0 || stats.PendingMismatch != 0 || stats.LifecycleMapUpdateFail != 0 {
		t.Fatalf("empty sum stats = %+v, want available zero counters", stats)
	}
}

func TestBPFStatsDiagnosticLineOnlyForNonZeroDrops(t *testing.T) {
	if line, ok := bpfStatsDiagnosticLine(bpfRuntimeStats{Available: true}); ok {
		t.Fatalf("zero counters produced diagnostic %q", line)
	}
	if line, ok := bpfStatsDiagnosticLine(bpfRuntimeStats{Available: false, Error: "nope"}); ok {
		t.Fatalf("unavailable stats produced diagnostic %q", line)
	}
	if line, ok := bpfStatsDiagnosticLine(bpfRuntimeStats{
		Available:              true,
		PayloadTruncatedEvents: 3,
	}); ok {
		t.Fatalf("truncated-only stats produced diagnostic %q", line)
	}
	line, ok := bpfStatsDiagnosticLine(bpfRuntimeStats{
		Available:              true,
		RingbufReserveFail:     5,
		RingbufCopyFail:        6,
		PendingUpdateFail:      7,
		OrphanExit:             8,
		PendingMismatch:        9,
		LifecycleMapUpdateFail: 10,
	})
	if !ok {
		t.Fatal("non-zero counters did not produce diagnostic")
	}
	for _, want := range []string{
		"ringbuf_reserve_fail=5",
		"ringbuf_copy_fail=6",
		"pending_update_fail=7",
		"orphan_exit=8",
		"pending_mismatch=9",
		"lifecycle_map_update_fail=10",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("diagnostic %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "payload_truncated") {
		t.Fatalf("diagnostic %q should not mention payload truncation", line)
	}
}
