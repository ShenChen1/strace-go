package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfMapGetNextKeyAttr(keyPtr, nextKeyPtr uint64) []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:4], 9)
	binary.LittleEndian.PutUint64(data[8:16], keyPtr)
	binary.LittleEndian.PutUint64(data[16:24], nextKeyPtr)
	return data
}

func TestBpfMapGetNextKeyUsesDirectionalPayloads(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 4
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 124, UserPtr: 0x4200, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte{0, 0, 0, 0}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 125, UserPtr: 0x4300, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte{1, 0, 0, 0}},
	}

	got := decodeBpfMapGetNextKey(ctx, makeBpfMapGetNextKeyAttr(0x4200, 0x4300), 24)
	if !strings.Contains(got, `key="\0\0\0\0"`) || !strings.Contains(got, `next_key="\1\0\0\0"`) {
		t.Fatalf("decodeBpfMapGetNextKey() = %q, want directional snapshots", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapGetNextKeyFailureIgnoresOutputPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 4
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 125, UserPtr: 0x4300, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte{1, 0, 0, 0}},
	}

	got := decodeBpfMapGetNextKey(ctx, makeBpfMapGetNextKeyAttr(0x4200, 0x4300), 24)
	if strings.Contains(got, `next_key="\1\0\0\0"`) || !strings.Contains(got, "next_key=0x4300") {
		t.Fatalf("decodeBpfMapGetNextKey() = %q, failure must preserve pointer", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
