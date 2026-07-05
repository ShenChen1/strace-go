package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeCachestatRange(off uint64, length uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], off)
	binary.LittleEndian.PutUint64(data[8:16], length)
	return data
}

func makeCachestatStats(values ...uint64) []byte {
	data := make([]byte, 40)
	for i, v := range values {
		if i >= 5 {
			break
		}
		binary.LittleEndian.PutUint64(data[i*8:i*8+8], v)
	}
	return data
}

func TestCachestatRangeDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeCachestatRange(5, 6)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "cachestat",
		Args:          [6]uint64{3, 0x1000, 0, 0},
		ProbeRetEnter: -1,
		Decoder:       decoder,
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("cstat_range = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestCachestatRangeIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeCachestatRange(99, 100)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "cachestat",
		Args:          [6]uint64{3, 0x1000, 0, 0},
		ProbeRetEnter: 0,
		Decoder:       decoder,
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("cstat_range = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestCachestatRangeUsesPayloadStructSection(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "cachestat",
		Args:    [6]uint64{3, 0x1000, 0, 0},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, Data: makeCachestatRange(7, 8)},
		},
		Decoder: event.NewDecoder(),
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if got.ArgParts[1] != "{off=0x7, len=8}" {
		t.Fatalf("cstat_range = %q", got.ArgParts[1])
	}
}

func TestCachestatStatsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeCachestatStats(1, 2, 3, 4, 5)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "cachestat",
		Args:         [6]uint64{3, 0, 0x2000, 0},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if got.ArgParts[2] != "0x2000" {
		t.Fatalf("cstat = %q, want pointer fallback", got.ArgParts[2])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestCachestatStatsUsesPayloadStructSection(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "cachestat",
		Args:    [6]uint64{3, 0, 0x2000, 0},
		Ret:     0,
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, UserPtr: 0x2000, Data: makeCachestatStats(1, 2, 3, 4, 5)},
		},
		Decoder: event.NewDecoder(),
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[2], "nr_cache=1") {
		t.Fatalf("cstat = %q", got.ArgParts[2])
	}
}

func TestCachestatStatsIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeCachestatStats(1, 2, 3, 4, 5)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "cachestat",
		Args:         [6]uint64{3, 0, 0x2000, 0},
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
	}

	got := (&CachestatHandler{}).Handle(ctx)
	if got.ArgParts[2] != "0x2000" {
		t.Fatalf("cstat = %q, want pointer fallback", got.ArgParts[2])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
