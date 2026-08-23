package main

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestConfigureBPFEventRingbufCapacityUsesConfiguredSize(t *testing.T) {
	tests := []struct {
		name       string
		maps       map[string]*ebpf.MapSpec
		wantSize   uint32
		wantErrSub string
	}{
		{
			name: "raises generated default",
			maps: map[string]*ebpf.MapSpec{
				bpfMapEvents: {Type: ebpf.RingBuf, MaxEntries: 1 << 28},
			},
			wantSize: traceDefaultEventRingbufCapacity,
		},
		{
			name: "normalizes larger generated size",
			maps: map[string]*ebpf.MapSpec{
				bpfMapEvents: {Type: ebpf.RingBuf, MaxEntries: traceDefaultEventRingbufCapacity + 4096},
			},
			wantSize: traceDefaultEventRingbufCapacity,
		},
		{
			name: "rejects missing events map",
			maps: map[string]*ebpf.MapSpec{
				"other": {Type: ebpf.Array, MaxEntries: 1},
			},
			wantErrSub: `BPF event map "events" is missing`,
		},
		{
			name: "rejects wrong map type",
			maps: map[string]*ebpf.MapSpec{
				bpfMapEvents: {Type: ebpf.Array, MaxEntries: 1},
			},
			wantErrSub: `BPF event map "events" has type`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := &ebpf.CollectionSpec{Maps: test.maps}
			err := configureBPFEventRingbufCapacity(spec, traceDefaultEventRingbufCapacity)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("configureBPFEventRingbufCapacity() error = %v, want substring %q", err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("configureBPFEventRingbufCapacity() error = %v, want nil", err)
			}
			if got := spec.Maps[bpfMapEvents].MaxEntries; got != test.wantSize {
				t.Fatalf("events MaxEntries = %d, want %d", got, test.wantSize)
			}
		})
	}
}

func TestConfigureBPFEventRingbufCapacityRejectsNilSpec(t *testing.T) {
	err := configureBPFEventRingbufCapacity(nil, traceDefaultEventRingbufCapacity)
	if err == nil || !strings.Contains(err.Error(), "BPF collection spec is nil") {
		t.Fatalf("configureBPFEventRingbufCapacity(nil) error = %v, want nil-spec error", err)
	}
}

func TestNormalizeTraceBPFConfigDefaultsRingbufCapacity(t *testing.T) {
	config, err := normalizeTraceBPFConfig(traceBPFConfig{})
	if err != nil {
		t.Fatalf("normalizeTraceBPFConfig() error = %v", err)
	}
	if config.eventRingbufCapacity != traceDefaultEventRingbufCapacity {
		t.Fatalf("default event ringbuf capacity = %d, want %d", config.eventRingbufCapacity, traceDefaultEventRingbufCapacity)
	}
}

func TestNormalizeTraceBPFConfigRejectsInvalidRingbufCapacity(t *testing.T) {
	for _, capacity := range []uint32{3, 1 << 19, 1 << 31} {
		config := traceBPFConfig{eventRingbufCapacity: capacity}
		if _, err := normalizeTraceBPFConfig(config); err == nil {
			t.Fatalf("normalizeTraceBPFConfig(%d) error = nil, want invalid capacity error", capacity)
		}
	}
}

func TestLoadBPFSpecWithTimingUsesSharedEventRingbufCapacity(t *testing.T) {
	const customCapacity uint32 = 1 << 20
	specs, err := loadBPFSpecWithTiming(systemTraceClock{}, nil, traceBPFConfig{
		eventRingbufCapacity: customCapacity,
	})
	if err != nil {
		t.Fatalf("loadBPFSpecWithTiming() error = %v", err)
	}
	if got := specs.core.Maps[bpfMapEvents].MaxEntries; got != customCapacity {
		t.Fatalf("core events MaxEntries = %d, want %d", got, customCapacity)
	}
	for family, spec := range specs.handlers {
		if got := spec.Maps[bpfMapEvents].MaxEntries; got != customCapacity {
			t.Fatalf("%s events MaxEntries = %d, want %d", family, got, customCapacity)
		}
	}
}
