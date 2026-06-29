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
		StrArgBuf:    make([]byte, BpfExitArgOffset+24),
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

func TestGetRobustListUsesExitSnapshotsWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0)}
	decoder := event.NewDecoder()
	ctx := newGetRobustListPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, robustListHeadOffset, makeUint64Snapshot(0xfeedface))
	putSmallSnapshot(ctx, robustListLenOffset, makeUint64Snapshot(24))

	got := (&GetRobustListHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[0xfeedface]" || got.ArgParts[2] != "[24]" {
		t.Fatalf("get_robust_list args = %v", got.ArgParts)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
