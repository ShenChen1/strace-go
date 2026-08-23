package main

const maxUint64 = ^uint64(0)

// producerAttemptLowerBound combines only observations available after the
// reader drains: delivered records plus reserve failures. It is intentionally
// a lower bound because copy failures and unread shutdown residue are separate.
func producerAttemptLowerBound(stats bpfRuntimeStats, reader traceEventReaderStats) uint64 {
	if !stats.Available {
		return 0
	}
	if reader.RecordsRead > maxUint64-stats.RingbufReserveFail {
		return maxUint64
	}
	return reader.RecordsRead + stats.RingbufReserveFail
}
