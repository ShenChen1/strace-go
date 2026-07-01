package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfRuntimeStats struct {
	RingbufOutputFail uint64
	Available         bool
	Error             string
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
		stats.RingbufOutputFail += value.RingbufOutputFail
	}
	return stats
}

func unavailableBPFStats(message string) bpfRuntimeStats {
	return bpfRuntimeStats{
		Available: false,
		Error:     message,
	}
}
