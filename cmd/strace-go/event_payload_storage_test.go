package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestTracePayloadStorageResetRetainsSmallBacking(t *testing.T) {
	storage := &tracePayloadStorage{
		sections: []handler.PayloadSection{{Data: make([]byte, 8)}},
	}
	storage.reset()
	dataCap := 0
	if cap(storage.sections) > 0 {
		dataCap = cap(storage.sections[:1][0].Data)
	}
	if cap(storage.sections) == 0 || dataCap != 8 {
		t.Fatalf("small payload backing was discarded: sections=%d data_cap=%d", cap(storage.sections), dataCap)
	}
}

func TestTracePayloadStorageResetDropsOversizedBacking(t *testing.T) {
	storage := &tracePayloadStorage{
		sections: []handler.PayloadSection{{Data: make([]byte, tracePayloadStorageMaxRetainedBytes+1)}},
	}
	storage.reset()
	dataCap := 0
	if cap(storage.sections) > 0 {
		dataCap = cap(storage.sections[:1][0].Data)
	}
	if cap(storage.sections) == 0 || dataCap != 0 {
		t.Fatalf("oversized payload backing was retained: data_cap=%d", dataCap)
	}
}
