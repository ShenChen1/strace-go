package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeStatSnapshot(ino uint64, mode uint32) []byte {
	data := make([]byte, statStructSize)
	binary.LittleEndian.PutUint64(data[8:16], ino)
	binary.LittleEndian.PutUint64(data[16:24], 1)
	binary.LittleEndian.PutUint32(data[24:28], mode)
	return data
}

func makeStatfsSnapshot(blockSize uint64) []byte {
	data := make([]byte, statfsStructSize)
	binary.LittleEndian.PutUint64(data[8:16], blockSize)
	return data
}

func newTypeStatPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "fstat",
		Args:         [6]uint64{3, 0x1000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		StrArgBuf:    make([]byte, BpfExitArgOffset+statStructSize),
	}
}

func TestDecodeStatDoesNotReadWhenSnapshotMissing(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeStatSnapshot(42, 0100644)}
	decoder := event.NewDecoder()
	ctx := newTypeStatPolicyContext(reader, decoder)

	got, ok := decodeStat(ctx, 1, "struct stat *", 0x1000)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeStat() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeStatUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeStatSnapshot(1, 0100644)}
	decoder := event.NewDecoder()
	ctx := newTypeStatPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeStatSnapshot(42, 0100644))

	got, ok := decodeStat(ctx, 1, "struct stat *", 0x1000)
	if !ok || !strings.Contains(got, "st_ino=42") {
		t.Fatalf("decodeStat() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeStatfsUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeStatfsSnapshot(1024)}
	decoder := event.NewDecoder()
	ctx := newTypeStatPolicyContext(reader, decoder)
	ctx.SysName = "fstatfs"
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeStatfsSnapshot(4096))

	got, ok := decodeStatfs(ctx, 1, "struct statfs *", 0x1000)
	if !ok || !strings.Contains(got, "f_bsize=4096") {
		t.Fatalf("decodeStatfs() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
