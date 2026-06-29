package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeFutexWaitvData(val uint64, addr uint64, flags uint32) []byte {
	data := make([]byte, futexWaitvSize)
	binary.LittleEndian.PutUint64(data[0:8], val)
	binary.LittleEndian.PutUint64(data[8:16], addr)
	binary.LittleEndian.PutUint32(data[16:20], flags)
	return data
}

func makeUint64Snapshot(v uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, v)
	return data
}

func putSmallSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func TestFutexTimeoutDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "futex",
		Args:          [6]uint64{0x2000, 0, 7, 0x1000},
		ProbeRetEnter: -1,
		Decoder:       decoder,
		StrArgBuf:     make([]byte, 16),
	}

	got := (&FutexHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("timeout = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexTimeoutUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "futex",
		Args:          [6]uint64{0x2000, 0, 7, 0x1000},
		ProbeRetEnter: 0,
		Decoder:       decoder,
		StrArgBuf:     make([]byte, 16),
	}
	putSmallSnapshot(ctx, BpfEnterArgOffset, makeTimeStruct(9, 10))

	got := (&FutexHandler{}).Handle(ctx)
	if got.ArgParts[3] != "{tv_sec=9, tv_nsec=10}" {
		t.Fatalf("timeout = %q", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitvDoesNotProbeLengthWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFutexWaitvData(1, 0x3000, 0)}
	decoder := event.NewDecoder()
	buf := append(makeFutexWaitvData(1, 0x3000, 0), makeFutexWaitvData(2, 0x4000, 0)...)
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{0x1000, 2},
		ProbeRetEnter: 0,
		DataLen:       uint32(len(buf)),
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "futex_waitv"},
		StrArgBuf:     buf,
	}

	got := formatFutexWaitvArray(ctx, 0, 0x1000, 2)
	if !strings.Contains(got, "val=0x2") {
		t.Fatalf("formatFutexWaitvArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitvDoesNotUseLegacyLengthProbe(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFutexWaitvData(1, 0x3000, 0)}
	buf := append(makeFutexWaitvData(1, 0x3000, 0), makeFutexWaitvData(2, 0x4000, 0)...)
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{0x1000, 2},
		ProbeRetEnter: 0,
		DataLen:       uint32(len(buf)),
		Decoder:       event.NewDecoder(),
		ScMeta:        meta.Syscall{Name: "futex_waitv"},
		StrArgBuf:     buf,
	}

	got := formatFutexWaitvArray(ctx, 0, 0x1000, 2)
	if !strings.Contains(got, "val=0x2") {
		t.Fatalf("formatFutexWaitvArray() = %q, want BPF snapshot length only", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func newArchPrctlPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "arch_prctl",
		Args:         [6]uint64{0x1003, 0x2000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		ScMeta: meta.Syscall{
			Args:     []string{"option", "arg2"},
			ArgTypes: []string{"int", "unsigned long"},
		},
		StrArgBuf: make([]byte, BpfExitArgOffset+8),
	}
}

func TestArchPrctlDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	decoder := event.NewDecoder()
	ctx := newArchPrctlPolicyContext(reader, decoder)

	got := (&ArchPrctlHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "[NULL]" {
		t.Fatalf("arch_prctl arg = %q, want NULL snapshot fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestArchPrctlUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	decoder := event.NewDecoder()
	ctx := newArchPrctlPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeUint64Snapshot(0x1234))

	got := (&ArchPrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[0x1234]" {
		t.Fatalf("arch_prctl arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
