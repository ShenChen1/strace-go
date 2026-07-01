package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfRuntimeStats struct {
	RingbufReserveFail uint64
	RingbufCopyFail    uint64
	Available          bool
	Error              string
}

func (s *traceSession) collectBPFStats() bpfRuntimeStats {
	if s == nil || s.bpfObjs == nil {
		return unavailableBPFStats("bpf objects unavailable")
	}
	return collectBPFStatsFromMap(s.bpfObjs.StatsMap)
}

func collectBPFStatsFromMap(statsMap *ebpf.Map) bpfRuntimeStats {
	if statsMap == nil {
		return unavailableBPFStats("stats map unavailable")
	}

	var values []bpfBpfStats
	if err := statsMap.Lookup(uint32(0), &values); err != nil {
		return unavailableBPFStats(fmt.Sprintf("stats map lookup failed: %v", err))
	}

	stats := bpfRuntimeStats{Available: true}
	for _, value := range values {
		stats.RingbufReserveFail += value.RingbufReserveFail
		stats.RingbufCopyFail += value.RingbufCopyFail
	}
	return stats
}

func unavailableBPFStats(message string) bpfRuntimeStats {
	return bpfRuntimeStats{
		Available: false,
		Error:     message,
	}
}
