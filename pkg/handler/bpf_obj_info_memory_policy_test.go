package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfObjInfoAttr(fd int32, ptr uint64, length uint32) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(fd))
	binary.LittleEndian.PutUint32(data[4:8], length)
	binary.LittleEndian.PutUint64(data[8:16], ptr)
	return data
}

func TestBpfObjGetInfoByFdUsesExitOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfObjInfoAttr(7, 0x2000, 64),
		0x2000: []byte("strace_go_map\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{15, 0x1000, 16}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   16,
			CopiedLen: 16,
			ProbeRet:  0,
			Data:      makeBpfObjInfoAttr(7, 0x2000, 64),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  113,
			UserPtr:   0x2000,
			UserLen:   64,
			CopiedLen: 17,
			ProbeRet:  0,
			Data:      []byte("strace_go_map\x00"),
		},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "info_data=") ||
		!strings.Contains(got.ArgParts[1], "strace_go_map") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want captured info data", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfObjGetInfoByFdIgnoresFailedExitOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{15, 0x1000, 16}
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   16,
			CopiedLen: 16,
			ProbeRet:  0,
			Data:      makeBpfObjInfoAttr(7, 0x2000, 64),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  113,
			UserPtr:   0x2000,
			UserLen:   64,
			CopiedLen: 17,
			ProbeRet:  0,
			Data:      []byte("strace_go_map\x00"),
		},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if strings.Contains(got.ArgParts[1], "info_data=") {
		t.Fatalf("BpfHandler.Handle() arg = %q, failed OUT payload must be ignored", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
