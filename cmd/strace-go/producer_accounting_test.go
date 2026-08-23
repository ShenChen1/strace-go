package main

import "testing"

func TestProducerAttemptLowerBoundAddsDeliveredAndReserveFailures(t *testing.T) {
	got := producerAttemptLowerBound(
		bpfRuntimeStats{Available: true, RingbufReserveFail: 7},
		traceEventReaderStats{RecordsRead: 13},
	)
	if got != 20 {
		t.Fatalf("producer attempt lower bound = %d, want 20", got)
	}
}

func TestProducerAttemptLowerBoundReturnsZeroWhenStatsUnavailable(t *testing.T) {
	got := producerAttemptLowerBound(
		bpfRuntimeStats{RingbufReserveFail: 7},
		traceEventReaderStats{RecordsRead: 13},
	)
	if got != 0 {
		t.Fatalf("producer attempt lower bound = %d, want unavailable zero", got)
	}
}

func TestProducerAttemptLowerBoundSaturatesOnOverflow(t *testing.T) {
	got := producerAttemptLowerBound(
		bpfRuntimeStats{Available: true, RingbufReserveFail: 1},
		traceEventReaderStats{RecordsRead: maxUint64},
	)
	if got != maxUint64 {
		t.Fatalf("producer attempt lower bound = %d, want saturation at %d", got, maxUint64)
	}
}
