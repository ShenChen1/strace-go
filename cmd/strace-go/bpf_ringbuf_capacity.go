package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// traceDefaultEventRingbufCapacity leaves enough burst room for the bounded
// high-rate workloads while keeping the capacity a power of two.
const traceDefaultEventRingbufCapacity uint32 = 1 << 29

const (
	traceMinEventRingbufCapacity uint32 = 1 << 20
	traceMaxEventRingbufCapacity uint32 = 1 << 30
)

func validateEventRingbufCapacity(capacity uint32) error {
	if capacity < traceMinEventRingbufCapacity || capacity > traceMaxEventRingbufCapacity {
		return fmt.Errorf("event ringbuf capacity %d is outside [%d, %d]", capacity, traceMinEventRingbufCapacity, traceMaxEventRingbufCapacity)
	}
	if capacity&(capacity-1) != 0 {
		return fmt.Errorf("event ringbuf capacity %d is not a power of two", capacity)
	}
	return nil
}

func configureBPFEventRingbufCapacity(spec *ebpf.CollectionSpec, capacity uint32) error {
	if err := validateEventRingbufCapacity(capacity); err != nil {
		return err
	}
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	events, ok := spec.Maps[bpfMapEvents]
	if !ok || events == nil {
		return fmt.Errorf("BPF event map %q is missing", bpfMapEvents)
	}
	if events.Type != ebpf.RingBuf {
		return fmt.Errorf("BPF event map %q has type %s, want ring buffer", bpfMapEvents, events.Type)
	}
	if events.MaxEntries != capacity {
		events.MaxEntries = capacity
	}
	return nil
}
