package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func TestPwritev2HandlerAddsIovecWriteHexDumpFromPayloadSections(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev2"
	ctx.Ret = 15
	ctx.ProbeRetExit = 0
	ctx.Args = [6]uint64{1, 0x1000, 3, 0, 0, 0}
	ctx.Opts = &cli.Options{StringLimit: 32, TraceWriteFDs: map[int32]bool{1: true}}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 3,
			CopiedLen: iovecSize * 3,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 3},
				[2]uint64{0x3000, 5},
				[2]uint64{0x4000, 7},
			),
		},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x2000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte("012")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x3000, UserLen: 5, CopiedLen: 5, ProbeRet: 0, Data: []byte("34567")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 2), UserPtr: 0x4000, UserLen: 7, CopiedLen: 7, ProbeRet: 0, Data: []byte("89abcde")},
	}

	dump := (&IoHandler{}).Handle(ctx).HexDumpStr

	for _, want := range []string{
		" * 3 bytes in buffer 0\n | 00000  30 31 32",
		" * 5 bytes in buffer 1\n | 00000  33 34 35 36 37",
		" * 7 bytes in buffer 2\n | 00000  38 39 61 62 63 64 65",
	} {
		if !strings.Contains(dump, want) {
			t.Fatalf("pwritev2 dump missing %q in:\n%s", want, dump)
		}
	}
}

func TestPwritev2HandlerSkipsIovecWriteHexDumpOnFailedReturn(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev2"
	ctx.Ret = -14
	ctx.ProbeRetExit = 0
	ctx.Args = [6]uint64{1, 0x1000, 1, 0, 0, 0}
	ctx.Opts = &cli.Options{StringLimit: 32, TraceWriteFDs: map[int32]bool{1: true}}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 3}),
		},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x2000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte("012")},
	}

	if dump := (&IoHandler{}).Handle(ctx).HexDumpStr; dump != "" {
		t.Fatalf("failed pwritev2 dump = %q, want empty", dump)
	}
}

func TestPreadv2HandlerAddsIovecReadHexDumpLimitedByReturnValue(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "preadv2"
	ctx.Ret = 7
	ctx.ProbeRetExit = 0
	ctx.Args = [6]uint64{0, 0x1000, 2, 8, 0, 0}
	ctx.Opts = &cli.Options{StringLimit: 32, TraceReadFDs: map[int32]bool{0: true}}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 2,
			CopiedLen: iovecSize * 2,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 8},
				[2]uint64{0x3000, 15},
			),
		},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x2000, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("89abcde\xff")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x3000, UserLen: 15, CopiedLen: 8, ProbeRet: 0, Data: []byte("\xff\xff\xff\xff\xff\xff\xff\xff")},
	}

	dump := (&IoHandler{}).Handle(ctx).HexDumpStr

	if !strings.Contains(dump, " * 7 bytes in buffer 0\n | 00000  38 39 61 62 63 64 65") {
		t.Fatalf("preadv2 dump did not include returned bytes:\n%s", dump)
	}
	if strings.Contains(dump, "buffer 1") || strings.Contains(dump, "ff ff") {
		t.Fatalf("preadv2 dump included bytes beyond return value:\n%s", dump)
	}
}
