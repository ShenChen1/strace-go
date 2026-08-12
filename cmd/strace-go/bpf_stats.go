package main

import (
	"fmt"
)

type bpfRuntimeStats struct {
	RingbufReserveFail     uint64
	RingbufCopyFail        uint64
	PayloadTruncatedEvents uint64
	PendingUpdateFail      uint64
	OrphanExit             uint64
	PendingMismatch        uint64
	LifecycleMapUpdateFail uint64
	Available              bool
	Error                  string
}

func collectBPFStatsFromReader(reader traceStatsReader) bpfRuntimeStats {
	if reader == nil {
		return unavailableBPFStats("stats reader unavailable")
	}

	var values []bpfBpfStats
	if err := reader.ReadStats(&values); err != nil {
		return unavailableBPFStats(fmt.Sprintf("stats map lookup failed: %v", err))
	}
	return sumBPFStatsValues(values)
}

func sumBPFStatsValues(values []bpfBpfStats) bpfRuntimeStats {
	stats := bpfRuntimeStats{Available: true}
	for _, value := range values {
		stats.RingbufReserveFail += value.RingbufReserveFail
		stats.RingbufCopyFail += value.RingbufCopyFail
		stats.PayloadTruncatedEvents += value.PayloadTruncatedEvents
		stats.PendingUpdateFail += value.PendingUpdateFail
		stats.OrphanExit += value.OrphanExit
		stats.PendingMismatch += value.PendingMismatch
		stats.LifecycleMapUpdateFail += value.LifecycleMapUpdateFail
	}
	return stats
}

func unavailableBPFStats(message string) bpfRuntimeStats {
	return bpfRuntimeStats{
		Available: false,
		Error:     message,
	}
}
