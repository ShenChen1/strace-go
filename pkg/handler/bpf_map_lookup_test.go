package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func TestBpfMapLookupUsesInputKeySnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 1
	ctx.PayloadSections = []PayloadSection{
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 139,
			UserPtr: 0x5200, UserLen: 4, CopiedLen: 4, ProbeRet: 0,
			Data: []byte{9, 0, 0, 0},
		},
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 117,
			UserPtr: 0x5300, UserLen: 4, CopiedLen: 4, ProbeRet: 0,
			Data: []byte("value"),
		},
	}

	attr := makeBpfMapLookupAttr()
	binary.LittleEndian.PutUint64(attr[8:16], 0x5200)
	binary.LittleEndian.PutUint64(attr[16:24], 0x5300)
	got := decodeBpfMapLookup(ctx, attr, 32)
	if !strings.Contains(got, `key="\t\0\0\0"`) {
		t.Fatalf("decodeBpfMapLookup() = %q, want key snapshot", got)
	}
	if !strings.Contains(got, `value="valu`) {
		t.Fatalf("decodeBpfMapLookup() = %q, want value snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapLookupFallsBackWhenKeySnapshotIsMissing(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 21
	ctx.PayloadSections = []PayloadSection{
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 117,
			UserPtr: 0x5300, UserLen: 4, CopiedLen: 4, ProbeRet: 0,
			Data: []byte("value"),
		},
	}
	attr := makeBpfMapLookupAttr()
	binary.LittleEndian.PutUint64(attr[8:16], 0x5200)
	binary.LittleEndian.PutUint64(attr[16:24], 0x5300)
	got := decodeBpfMapLookup(ctx, attr, 32)
	if !strings.Contains(got, "key=0x5200") {
		t.Fatalf("decodeBpfMapLookup() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
