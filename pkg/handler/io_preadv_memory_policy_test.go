package handler

import (
	"testing"

	"strace-go/pkg/event"
)

func TestPreadvHandlerUsesNestedIovecBaseOutPayload(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "preadv"
	ctx.Opts.StringLimit = 8
	ctx.Ret = 23
	ctx.Args = [6]uint64{0, 0x1000, 2, 0xdefaceddeadbeef}
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
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  iovecBasePayloadArgIndex(1, 0),
			UserPtr:   0x2000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      []byte("01234567"),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  iovecBasePayloadArgIndex(1, 1),
			UserPtr:   0x3000,
			UserLen:   15,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      []byte("89abcdef"),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{
		"0",
		`[{iov_base="01234567", iov_len=8}, {iov_base="89abcdef"..., iov_len=15}]`,
		"2",
		"1004211379570065135",
	}
	if len(got) != len(want) {
		t.Fatalf("preadv arg count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("preadv arg %d = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}

func TestPreadvHandlerLimitsOutPayloadByReturnValue(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "preadv"
	ctx.Opts.StringLimit = 32
	ctx.Ret = 7
	ctx.Args = [6]uint64{3, 0x1000, 2, 8}
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
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  iovecBasePayloadArgIndex(1, 0),
			UserPtr:   0x2000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      []byte("89abcde\xff"),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  iovecBasePayloadArgIndex(1, 1),
			UserPtr:   0x3000,
			UserLen:   15,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      []byte("\xff\xff\xff\xff\xff\xff\xff\xff"),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{
		"3",
		`[{iov_base="89abcde", iov_len=8}, {iov_base="", iov_len=15}]`,
		"2",
		"8",
	}
	if len(got) != len(want) {
		t.Fatalf("preadv arg count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("preadv arg %d = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}

func TestPreadvHandlerUsesFourArgSignedNegativeOffsetContract(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "preadv"
	ctx.Args = [6]uint64{0, 0x1000, 1, ^uint64(0)}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 8}),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{"0", "[{iov_base=0x2000, iov_len=8}]", "1", "-1"}
	if len(got) != len(want) {
		t.Fatalf("preadv arg count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("preadv arg %d = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}
