package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makePrctlUint32Snapshot(v uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, v)
	return data
}

func makePrctlNameSnapshot(name string) []byte {
	data := make([]byte, prctlNameSize)
	copy(data, name)
	return data
}

func newPrctlPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder, option uint64) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "prctl",
		Args:          [6]uint64{option, 0x1000},
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
		Opts:          &cli.Options{StringLimit: 32},
	}
}

func TestPrctlPdeathsigDoesNotReadWhenSnapshotMissing(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlUint32Snapshot(15)}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 1)

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("PR_GET_PDEATHSIG arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlPdeathsigIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlUint32Snapshot(15)}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 1)
	ctx.ProbeRetExit = 0

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("PR_GET_PDEATHSIG arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlPdeathsigUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlUint32Snapshot(1)}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 1)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makePrctlUint32Snapshot(15)},
	}

	got := (&PrctlHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "TERM") {
		t.Fatalf("PR_GET_PDEATHSIG arg = %q, want SIGTERM-ish decode", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlGetIntIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlUint32Snapshot(1)}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 37)
	ctx.ProbeRetExit = 0

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("PR_GET_CHILD_SUBREAPER arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlGetIntUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlUint32Snapshot(0)}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 37)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makePrctlUint32Snapshot(1)},
	}

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[1]" {
		t.Fatalf("PR_GET_CHILD_SUBREAPER arg = %q, want [1]", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlGetNameIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlNameSnapshot("worker")}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 16)
	ctx.ProbeRetExit = 0

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("PR_GET_NAME arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlGetNameUsesPayloadStringSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlNameSnapshot("fallback")}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 16)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: []byte("worker\x00")},
	}

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "\"worker\"" {
		t.Fatalf("PR_GET_NAME arg = %q, want quoted worker", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlSetNameIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlNameSnapshot("worker")}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 15)
	ctx.ProbeRetEnter = 0

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("PR_SET_NAME arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlSetNameUsesPayloadStringSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlNameSnapshot("fallback")}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 15)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("worker\x00")},
	}

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "\"worker\"" {
		t.Fatalf("PR_SET_NAME arg = %q, want quoted worker", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPrctlSetNameMarksFilledKernelNameSnapshotTruncated(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePrctlNameSnapshot("fallback")}
	decoder := event.NewDecoder()
	ctx := newPrctlPolicyContext(reader, decoder, 15)
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserLen:   prctlNameSize,
			CopiedLen: prctlDisplayNameLimit,
			ProbeRet:  0,
			Data:      []byte("123456789abcdef"),
		},
	}

	got := (&PrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "\"123456789abcdef\"..." {
		t.Fatalf("PR_SET_NAME arg = %q, want truncated quoted name", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
