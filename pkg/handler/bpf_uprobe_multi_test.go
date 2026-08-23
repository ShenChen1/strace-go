package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfUprobeMultiAttr() []byte {
	data := make([]byte, 60)
	binary.LittleEndian.PutUint32(data[8:12], 48)
	binary.LittleEndian.PutUint64(data[16:24], 0x1000)
	binary.LittleEndian.PutUint64(data[24:32], 0x2000)
	binary.LittleEndian.PutUint64(data[32:40], 0x3000)
	binary.LittleEndian.PutUint64(data[40:48], 0x4000)
	binary.LittleEndian.PutUint32(data[48:52], 2)
	binary.LittleEndian.PutUint32(data[52:56], 1)
	binary.LittleEndian.PutUint32(data[56:60], 1234)
	return data
}

func TestBpfUprobeMultiUsesEventPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: []byte("reader-must-not-run\x00"),
		0x2000: makeBpfU64Array(0x111, 0x222),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 133, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("/tmp/uprobe-fixture\x00")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 134, UserPtr: 0x2000, UserLen: 16, CopiedLen: 16, ProbeRet: 0, Data: makeBpfU64Array(0x111, 0x222)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 135, UserPtr: 0x3000, UserLen: 16, CopiedLen: 16, ProbeRet: 0, Data: makeBpfU64Array(0x333, 0x444)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 136, UserPtr: 0x4000, UserLen: 16, CopiedLen: 16, ProbeRet: 0, Data: makeBpfU64Array(0x555, 0x666)},
	}

	got := decodeBpfLinkCreate(ctx, makeBpfUprobeMultiAttr(), 60)
	for _, want := range []string{
		`path="/tmp/uprobe-fixture"`,
		"offsets=[0x111, 0x222]",
		"ref_ctr_offsets=[0x333, 0x444]",
		"cookies=[0x555, 0x666]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfLinkCreate() = %q, missing %q", got, want)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfUprobeMultiFallsBackToPointersWithoutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: []byte("reader-must-not-run\x00"),
		0x2000: makeBpfU64Array(0x111, 0x222),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfLinkCreate(ctx, makeBpfUprobeMultiAttr(), 60)
	for _, want := range []string{
		"path=0x1000",
		"offsets=0x2000",
		"ref_ctr_offsets=0x3000",
		"cookies=0x4000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfLinkCreate() = %q, missing %q", got, want)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
