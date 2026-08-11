package main

import (
	"fmt"

	"github.com/cilium/ebpf"
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

func collectBPFStatsFromObjects(objs *bpfObjects) bpfRuntimeStats {
	if objs == nil {
		return unavailableBPFStats("bpf objects unavailable")
	}
	return collectBPFStatsFromMap(objs.StatsMap)
}

func collectBPFStatsFromMap(statsMap *ebpf.Map) bpfRuntimeStats {
	if statsMap == nil {
		return unavailableBPFStats("stats map unavailable")
	}

	var values []bpfBpfStats
	if err := statsMap.Lookup(uint32(0), &values); err != nil {
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
