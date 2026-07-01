package handler

import (
	"testing"

	"strace-go/pkg/event"
)

func newGetRobustListPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "get_robust_list",
		Args:         [6]uint64{0, 0x1000, 0x2000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
	}
}

func TestGetRobustListDoesNotReadWhenSnapshotMissing(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	decoder := event.NewDecoder()
	ctx := newGetRobustListPolicyContext(reader, decoder)

	got := (&GetRobustListHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" || got.ArgParts[2] != "0x2000" {
		t.Fatalf("get_robust_list args = %v", got.ArgParts)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestGetRobustListIgnoresLegacyFixedSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0)}
	decoder := event.NewDecoder()
	ctx := newGetRobustListPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	ctx.StrArgBuf = make([]byte, BpfExitArgOffset+24)
	putSmallSnapshot(ctx, BpfExitArgOffset, makeUint64Snapshot(0xfeedface))
	putSmallSnapshot(ctx, BpfExitArgOffset+16, makeUint64Snapshot(24))

	got := (&GetRobustListHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" || got.ArgParts[2] != "0x2000" {
		t.Fatalf("get_robust_list args = %v, want raw pointers", got.ArgParts)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestGetRobustListUsesPayloadStructSections(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0)}
	ctx := newGetRobustListPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeUint64Snapshot(0xbeefcafe)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: makeUint64Snapshot(32)},
	}

	got := (&GetRobustListHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[0xbeefcafe]" || got.ArgParts[2] != "[32]" {
		t.Fatalf("get_robust_list args = %v", got.ArgParts)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
