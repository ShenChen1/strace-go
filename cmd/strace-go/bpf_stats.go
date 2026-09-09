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
	OrphanFirstPid         uint64
	OrphanFirstTid         uint64
	OrphanFirstSysID       uint64
	OrphanFirstRet         int64
	OrphanFirstReason      uint64
	OrphanFirstTimeNS      uint64
	OrphanLastPid          uint64
	OrphanLastTid          uint64
	OrphanLastSysID        uint64
	OrphanLastRet          int64
	OrphanLastReason       uint64
	OrphanLastTimeNS       uint64
	PendingMismatch        uint64
	LifecycleMapUpdateFail uint64
	LifecycleForkSeen      uint64
	LifecycleForkTracked   uint64
	LifecycleForkUntracked uint64
	LifecycleForkInstalled uint64
	LifecycleForkFailed    uint64
	LifecycleExecSeen      uint64
	LifecycleExecUntracked uint64
	LifecycleExitSeen      uint64
	LifecycleExitUntracked uint64
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
		if value.OrphanFirstTimeNs > 0 &&
			(stats.OrphanFirstTimeNS == 0 || value.OrphanFirstTimeNs < stats.OrphanFirstTimeNS) {
			stats.OrphanFirstPid = value.OrphanFirstPid
			stats.OrphanFirstTid = value.OrphanFirstTid
			stats.OrphanFirstSysID = value.OrphanFirstSysId
			stats.OrphanFirstRet = value.OrphanFirstRet
			stats.OrphanFirstReason = value.OrphanFirstReason
			stats.OrphanFirstTimeNS = value.OrphanFirstTimeNs
		}
		if value.OrphanLastTimeNs > stats.OrphanLastTimeNS {
			stats.OrphanLastPid = value.OrphanLastPid
			stats.OrphanLastTid = value.OrphanLastTid
			stats.OrphanLastSysID = value.OrphanLastSysId
			stats.OrphanLastRet = value.OrphanLastRet
			stats.OrphanLastReason = value.OrphanLastReason
			stats.OrphanLastTimeNS = value.OrphanLastTimeNs
		}
		stats.PendingMismatch += value.PendingMismatch
		stats.LifecycleMapUpdateFail += value.LifecycleMapUpdateFail
		stats.LifecycleForkSeen += value.LifecycleForkSeen
		stats.LifecycleForkTracked += value.LifecycleForkParentTracked
		stats.LifecycleForkUntracked += value.LifecycleForkParentUntracked
		stats.LifecycleForkInstalled += value.LifecycleForkChildFilterInstalled
		stats.LifecycleForkFailed += value.LifecycleForkChildFilterFailed
		stats.LifecycleExecSeen += value.LifecycleExecSeen
		stats.LifecycleExecUntracked += value.LifecycleExecUntracked
		stats.LifecycleExitSeen += value.LifecycleExitSeen
		stats.LifecycleExitUntracked += value.LifecycleExitUntracked
	}
	return stats
}

func unavailableBPFStats(message string) bpfRuntimeStats {
	return bpfRuntimeStats{
		Available: false,
		Error:     message,
	}
}
