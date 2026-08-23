package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func TestBpfMapDeleteBatchUsesInputKeysOnly(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 27
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 121, UserPtr: 0x4100, UserLen: 10, CopiedLen: 10, ProbeRet: 0, Data: []byte("delete-key")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 122, UserPtr: 0x5200, UserLen: 12, CopiedLen: 12, ProbeRet: 0, Data: []byte("must-ignore")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 119, UserPtr: 0x5300, UserLen: 12, CopiedLen: 12, ProbeRet: 0, Data: []byte("must-ignore")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	if !strings.Contains(got, `keys="delete-key"`) {
		t.Fatalf("decodeBpfMapBatch() = %q, want delete keys snapshot", got)
	}
	if strings.Contains(got, "must-ignore") || strings.Contains(got, "values=") {
		t.Fatalf("decodeBpfMapBatch() = %q, delete batch must not render values", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
