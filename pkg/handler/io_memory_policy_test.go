package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func newIovecPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "readv",
		Decoder: decoder,
		Opts:    &cli.Options{StringLimit: 32},
	}
}

func TestDecodeIovecArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("DecodeIovecArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("DecodeIovecArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayUsesPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
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
	}

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "[{iov_base=0x2000, iov_len=3}]" {
		t.Fatalf("DecodeIovecArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayUsesRemoteProcessVMPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x4000, 7})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
	ctx.SysName = "process_vm_readv"
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  3,
			UserPtr:   0x3000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x4000, 7}),
		},
	}

	got := DecodeIovecArray(ctx, 3, 0x3000, 1)
	if got != "[{iov_base=0x4000, iov_len=7}]" {
		t.Fatalf("DecodeIovecArray remote = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeProcessVMWritevUsesNestedLocalIovecBasePayload(t *testing.T) {
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, decoder)
	ctx.SysName = "process_vm_writev"
	ctx.Opts.StringLimit = 5
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
				[2]uint64{0x2000, 2},
				[2]uint64{0x3000, 3},
				[2]uint64{0x4000, 6},
			),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  iovecBasePayloadArgIndex(1, 0),
			UserPtr:   0x2000,
			UserLen:   2,
			CopiedLen: 2,
			ProbeRet:  0,
			Data:      []byte{0x80, 0x81},
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  iovecBasePayloadArgIndex(1, 1),
			UserPtr:   0x3000,
			UserLen:   3,
			CopiedLen: 3,
			ProbeRet:  0,
			Data:      []byte{0x82, 0x83, 0x84},
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  iovecBasePayloadArgIndex(1, 2),
			UserPtr:   0x4000,
			UserLen:   6,
			CopiedLen: 5,
			ProbeRet:  0,
			Data:      []byte{0x85, 0x86, 0x87, 0x88, 0x89},
		},
	}

	got := DecodeIovecArray(ctx, 1, 0x1000, 3)
	want := `[{iov_base="\200\201", iov_len=2}, {iov_base="\202\203\204", iov_len=3}, {iov_base="\205\206\207\210\211"..., iov_len=6}]`
	if got != want {
		t.Fatalf("DecodeIovecArray() = %q, want %q", got, want)
	}
}

func TestDecodeProcessVMReadvUsesNestedLocalIovecBaseOutPayload(t *testing.T) {
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, decoder)
	ctx.SysName = "process_vm_readv"
	ctx.Opts.StringLimit = 5
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 7}),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  iovecBasePayloadArgIndex(1, 0),
			UserPtr:   0x2000,
			UserLen:   7,
			CopiedLen: 5,
			ProbeRet:  0,
			Data:      []byte{0x80, 0x81, 0x82, 0x83, 0x84},
		},
	}

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	want := `[{iov_base="\200\201\202\203\204"..., iov_len=7}]`
	if got != want {
		t.Fatalf("DecodeIovecArray readv = %q, want %q", got, want)
	}
}

func TestDecodeProcessVMWritevKeepsRemoteIovecBaseAsAddress(t *testing.T) {
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, decoder)
	ctx.SysName = "process_vm_writev"
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  3,
			UserPtr:   0x1000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 2}),
		},
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  iovecBasePayloadArgIndex(3, 0),
			UserPtr:   0x2000,
			UserLen:   2,
			CopiedLen: 2,
			ProbeRet:  0,
			Data:      []byte{0x80, 0x81},
		},
	}

	got := DecodeIovecArray(ctx, 3, 0x1000, 1)
	if got != "[{iov_base=0x2000, iov_len=2}]" {
		t.Fatalf("DecodeIovecArray remote = %q", got)
	}
}

func TestDecodeProcessVMIovecAddsAddressCommentForProbeTruncatedArray(t *testing.T) {
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, decoder)
	ctx.SysName = "process_vm_writev"
	ctx.Opts.StringLimit = 5
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  3,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 6,
			CopiedLen: iovecSize * 5,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 2},
				[2]uint64{0x3000, 3},
				[2]uint64{0x4000, 4},
				[2]uint64{0x5000, 5},
				[2]uint64{0x6000, 6},
			),
		},
	}

	got := DecodeIovecArray(ctx, 3, 0x1000, 6)
	want := "[{iov_base=0x2000, iov_len=2}, {iov_base=0x3000, iov_len=3}, {iov_base=0x4000, iov_len=4}, {iov_base=0x5000, iov_len=5}, {iov_base=0x6000, iov_len=6}, ... /* 0x1050 */]"
	if got != want {
		t.Fatalf("DecodeIovecArray truncated process_vm = %q, want %q", got, want)
	}
}

func TestDecodeProcessVMIovecUsesDisplayLimitWithoutAddressComment(t *testing.T) {
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, decoder)
	ctx.SysName = "process_vm_writev"
	ctx.Opts.StringLimit = 5
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  3,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 6,
			CopiedLen: iovecSize * 6,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 2},
				[2]uint64{0x3000, 3},
				[2]uint64{0x4000, 4},
				[2]uint64{0x5000, 5},
				[2]uint64{0x6000, 6},
				[2]uint64{0x7000, 7},
			),
		},
	}

	got := DecodeIovecArray(ctx, 3, 0x1000, 6)
	want := "[{iov_base=0x2000, iov_len=2}, {iov_base=0x3000, iov_len=3}, {iov_base=0x4000, iov_len=4}, {iov_base=0x5000, iov_len=5}, {iov_base=0x6000, iov_len=6}, ...]"
	if got != want {
		t.Fatalf("DecodeIovecArray display-limited process_vm = %q, want %q", got, want)
	}
}

func TestPwritevHandlerUsesFourArgSignedOffsetContract(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev"
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
		t.Fatalf("pwritev arg count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pwritev arg %d = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}

func TestPwritevHandlerUsesNestedIovecBasePayloadAndStringLimit(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev"
	ctx.Opts.StringLimit = 32
	ctx.Args = [6]uint64{0, 0x1000, 8, 0xdefaceddeadbeef}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 8,
			CopiedLen: iovecSize * 8,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 8},
				[2]uint64{0x3000, 7},
				[2]uint64{0x4000, 6},
				[2]uint64{0x5000, 5},
				[2]uint64{0x6000, 4},
				[2]uint64{0x7000, 3},
				[2]uint64{0x8000, 2},
				[2]uint64{0x9000, 1},
			),
		},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x2000, UserLen: 8, CopiedLen: 7, ProbeRet: 0, Data: []byte{0, 1, 2, 3, 4, 5, 6}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x3000, UserLen: 7, CopiedLen: 7, ProbeRet: 0, Data: []byte{1, 2, 3, 4, 5, 6, 7}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 2), UserPtr: 0x4000, UserLen: 6, CopiedLen: 6, ProbeRet: 0, Data: []byte{2, 3, 4, 5, 6, 7}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 3), UserPtr: 0x5000, UserLen: 5, CopiedLen: 5, ProbeRet: 0, Data: []byte{3, 4, 5, 6, 7}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 4), UserPtr: 0x6000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte{4, 5, 6, 7}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 5), UserPtr: 0x7000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte{5, 6, 7}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 6), UserPtr: 0x8000, UserLen: 2, CopiedLen: 2, ProbeRet: 0, Data: []byte{6, 7}},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	wantVec := `[{iov_base="\0\1\2\3\4\5\6"..., iov_len=8}, {iov_base="\1\2\3\4\5\6\7", iov_len=7}, {iov_base="\2\3\4\5\6\7", iov_len=6}, {iov_base="\3\4\5\6\7", iov_len=5}, {iov_base="\4\5\6\7", iov_len=4}, {iov_base="\5\6\7", iov_len=3}, {iov_base="\6\7", iov_len=2}, ...]`
	if len(got) != 4 || got[1] != wantVec {
		t.Fatalf("pwritev args = %#v, want vec %q", got, wantVec)
	}
	if got[3] != "1004211379570065135" {
		t.Fatalf("pwritev offset = %q", got[3])
	}
}

func TestPwritevHandlerDisplayLimitSuppressesLateProbeAddressComment(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev"
	ctx.Opts.StringLimit = 7
	ctx.Args = [6]uint64{0, 0x1000, 9, 0}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 9,
			CopiedLen: iovecSize * 7,
			ProbeRet:  0,
			Data: iovecBytes(
				[2]uint64{0x2000, 8},
				[2]uint64{0x3000, 7},
				[2]uint64{0x4000, 6},
				[2]uint64{0x5000, 5},
				[2]uint64{0x6000, 4},
				[2]uint64{0x7000, 3},
				[2]uint64{0x8000, 2},
			),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	if len(got) != 4 {
		t.Fatalf("pwritev arg count = %d, want 4: %#v", len(got), got)
	}
	if strings.Contains(got[1], "/* 0x") {
		t.Fatalf("pwritev display-limit ellipsis = %q, want no address comment", got[1])
	}
}

func TestDecodeIovecArrayUsesPartialPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize * 2,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 3}),
		},
	}

	got := DecodeIovecArray(ctx, 1, 0x1000, 2)
	if got != "[{iov_base=0x2000, iov_len=3}, ... /* 0x1010 */]" {
		t.Fatalf("DecodeIovecArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayFallsBackWithoutPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "writev",
		ProbeRetEnter: 0,
		Decoder:       event.NewDecoder(),
		Opts:          &cli.Options{StringLimit: 32},
	}

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("DecodeIovecArray() = %q, want pointer fallback", got)
	}
}

func TestProcessMadviseIovecDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Decoder: decoder,
	}

	got := formatProcessMadviseIovec(ctx, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("formatProcessMadviseIovec() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestProcessMadviseIovecIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		ProbeRetEnter: 0,
		Decoder:       decoder,
	}

	got := formatProcessMadviseIovec(ctx, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("formatProcessMadviseIovec() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
