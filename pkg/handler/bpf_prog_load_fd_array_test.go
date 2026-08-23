package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgLoadFDArrayAttrForTest(ptr uint64, count uint32) []byte {
	data := make([]byte, 168)
	binary.LittleEndian.PutUint64(data[120:128], ptr)
	binary.LittleEndian.PutUint32(data[148:152], count)
	return data
}

func TestBpfProgLoadFDArrayUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: {17, 0, 0, 0, 23, 0, 0, 0},
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  141,
			UserPtr:   0x6000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      reader.data[0x6000],
		},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFDArrayAttrForTest(0x6000, 2), 168)
	if !strings.Contains(got, "fd_array=[17, 23]") {
		t.Fatalf("decodeBpfProgLoad() = %q, want fd array snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFDArrayFallsBackToPointerWithoutValidPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: {17, 0, 0, 0, 23, 0, 0, 0},
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  141,
			UserPtr:   0x6000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      reader.data[0x6000],
		},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFDArrayAttrForTest(0x6000, 2), 168)
	if !strings.Contains(got, "fd_array=0x6000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFDArrayFallsBackWhenCountIsUnavailable(t *testing.T) {
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	data := make([]byte, 128)
	binary.LittleEndian.PutUint64(data[120:128], 0x6000)

	got := decodeBpfProgLoad(ctx, data, uint32(len(data)))
	if !strings.Contains(got, "fd_array=0x6000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFDArrayIgnoresIncompletePayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  141,
			UserPtr:   0x6000,
			UserLen:   4,
			CopiedLen: 4,
			ProbeRet:  0,
			Data:      []byte{17, 0, 0, 0},
		},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFDArrayAttrForTest(0x6000, 2), 168)
	if !strings.Contains(got, "fd_array=[17, ...") {
		t.Fatalf("decodeBpfProgLoad() = %q, incomplete payload must preserve bounded prefix", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
