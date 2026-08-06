package main

import "testing"

func TestZeroEventTypeIsNotExit(t *testing.T) {
	envelope := traceEventEnvelope{
		valid:        true,
		eventVersion: traceEventV2Version,
		eventType:    0,
	}

	if envelope.isExit() {
		t.Fatal("event_type=0 should not be treated as an explicit exit event")
	}
	if got := bpfEventTypeNameFromID(envelope.eventType); got != "unknown" {
		t.Fatalf("bpfEventTypeNameFromID(event_type=0) = %q, want unknown", got)
	}
}
