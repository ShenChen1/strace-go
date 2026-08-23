package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfGetNextIDAttrForTest(startID, nextID uint32) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], startID)
	binary.LittleEndian.PutUint32(data[4:8], nextID)
	return data
}

func TestBpfGetNextIDUsesExitScalarSnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: makeBpfGetNextIDAttrForTest(7, 7),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{12, 0x5000, 8}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x5000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      makeBpfGetNextIDAttrForTest(7, 7),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  140,
			UserPtr:   0x5004,
			UserLen:   4,
			CopiedLen: 4,
			ProbeRet:  0,
			Data:      makeBpfGetNextIDAttrForTest(42, 0)[0:4],
		},
	}

	got := decodeBpfGetNextId(ctx, makeBpfGetNextIDAttrForTest(7, 7), 8)
	if !strings.Contains(got, "start_id=7") || !strings.Contains(got, "next_id=42") {
		t.Fatalf("decodeBpfGetNextId() = %q, want exit next_id", got)
	}
	if strings.Contains(got, "next_id=7") {
		t.Fatalf("decodeBpfGetNextId() = %q, used stale enter next_id", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfGetNextIDFallsBackWithoutValidExitSnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{12, 0x5000, 8}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x5000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      makeBpfGetNextIDAttrForTest(7, 7),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  140,
			UserPtr:   0x5004,
			UserLen:   4,
			CopiedLen: 4,
			ProbeRet:  0,
			Data:      []byte{42, 0, 0, 0},
		},
	}

	got := decodeBpfGetNextId(ctx, makeBpfGetNextIDAttrForTest(7, 7), 8)
	if !strings.Contains(got, "next_id=7") || strings.Contains(got, "next_id=42") {
		t.Fatalf("decodeBpfGetNextId() = %q, invalid exit snapshot must be ignored", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
