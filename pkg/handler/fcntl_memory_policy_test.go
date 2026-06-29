package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeFlockData(lockType uint16, start uint64, length uint64, pid uint32) []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint16(data[0:2], lockType)
	binary.LittleEndian.PutUint16(data[2:4], 0)
	binary.LittleEndian.PutUint64(data[8:16], start)
	binary.LittleEndian.PutUint64(data[16:24], length)
	binary.LittleEndian.PutUint32(data[24:28], pid)
	return data
}

func makeUint64Data(v uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, v)
	return data
}

func makeFOwnerExData(ownerType uint32, pid uint32) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], ownerType)
	binary.LittleEndian.PutUint32(data[4:8], pid)
	return data
}

func makeDelegationData(flags uint32, lockType uint16) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], flags)
	binary.LittleEndian.PutUint16(data[4:6], lockType)
	return data
}

func newFcntlPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "fcntl",
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		StrArgBuf:     make([]byte, BpfExitArgOffset+32),
	}
}

func putFcntlSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func TestFcntlFlockDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFlockData(1, 2, 3, 4)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)

	got := (&FcntlHandler{}).decodeFlock(ctx, "F_SETLK", 0x1000)
	if got != "0x1000" {
		t.Fatalf("decodeFlock() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlFlockUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFlockData(1, 2, 3, 4)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	putFcntlSnapshot(ctx, BpfEnterArgOffset, makeFlockData(1, 2, 3, 4))

	got := (&FcntlHandler{}).decodeFlock(ctx, "F_SETLK", 0x1000)
	if !strings.Contains(got, "l_type=F_WRLCK") {
		t.Fatalf("decodeFlock() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlFlockUsesExitSnapshotWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFlockData(1, 2, 3, 4)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putFcntlSnapshot(ctx, BpfExitArgOffset, makeFlockData(2, 5, 6, 7))

	got := (&FcntlHandler{}).decodeFlock(ctx, "F_GETLK", 0x1000)
	if !strings.Contains(got, "l_type=F_UNLCK") || !strings.Contains(got, "l_pid=7") {
		t.Fatalf("decodeFlock() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlFOwnerExDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFOwnerExData(1, 42)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)

	got := (&FcntlHandler{}).decodeFOwnerEx(ctx, 0x1000, false)
	if got != "0x1000" {
		t.Fatalf("decodeFOwnerEx() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlFOwnerExUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFOwnerExData(1, 42)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putFcntlSnapshot(ctx, BpfExitArgOffset, makeFOwnerExData(1, 42))

	got := (&FcntlHandler{}).decodeFOwnerEx(ctx, 0x1000, true)
	if got != "{type=F_OWNER_PID, pid=42}" {
		t.Fatalf("decodeFOwnerEx() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlRwHintDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Data(3)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)

	got := (&FcntlHandler{}).decodeRwHint(ctx, 0x1000, false)
	if got != "0x1000" {
		t.Fatalf("decodeRwHint() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlRwHintUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Data(3)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	putFcntlSnapshot(ctx, BpfEnterArgOffset, makeUint64Data(3))

	got := (&FcntlHandler{}).decodeRwHint(ctx, 0x1000, false)
	if got != "[RWH_WRITE_LIFE_MEDIUM]" {
		t.Fatalf("decodeRwHint() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlDelegationDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDelegationData(1, 1)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)

	got := (&FcntlHandler{}).decodeDelegation(ctx, 0x1000, false)
	if got != "0x1000" {
		t.Fatalf("decodeDelegation() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFcntlDelegationUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDelegationData(1, 1)}
	decoder := event.NewDecoder()
	ctx := newFcntlPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	putFcntlSnapshot(ctx, BpfEnterArgOffset, makeDelegationData(1, 1))

	got := (&FcntlHandler{}).decodeDelegation(ctx, 0x1000, false)
	if !strings.Contains(got, "d_flags=0x1") || !strings.Contains(got, "d_type=F_WRLCK") {
		t.Fatalf("decodeDelegation() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
