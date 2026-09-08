package handler

import (
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestPreadv2HandlerUsesFiveArgOffsetAndFlagsContract(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "preadv2"
	cliOptionsForTest(ctx).StringLimit = 8
	ctx.Ret = 8
	ctx.Args = [6]uint64{0, 0x1000, 1, 0x7ac5fed6dad7bef8, 0xbadc0deddeadbeef, 1}
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
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{
		"0",
		`[{iov_base="01234567", iov_len=8}]`,
		"1",
		"8846757241787236088",
		"RWF_HIPRI",
	}
	assertArgParts(t, "preadv2", got, want)
}

func TestPwritev2HandlerUsesFiveArgOffsetAndFlagsContract(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev2"
	cliOptionsForTest(ctx).StringLimit = 8
	ctx.Args = [6]uint64{1, 0x1000, 1, ^uint64(0), 0, 3}
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
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  iovecBasePayloadArgIndex(1, 0),
			UserPtr:   0x2000,
			UserLen:   8,
			CopiedLen: 7,
			ProbeRet:  0,
			Data:      []byte("0123456"),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{
		"1",
		`[{iov_base="0123456"..., iov_len=8}]`,
		"1",
		"-1",
		"RWF_HIPRI|RWF_DSYNC",
	}
	assertArgParts(t, "pwritev2", got, want)
}

func TestPwritev2HandlerPrintsZeroRwfFlagsAsZero(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "pwritev2"
	ctx.Args = [6]uint64{1, 0, 0, 0, 0, 0}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{"1", "NULL", "0", "0", "0"}
	assertArgParts(t, "pwritev2 zero flags", got, want)
}

func TestReadvHandlerFormatsEmptyBuffersOnZeroReturn(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "readv"
	ctx.Ret = 0
	ctx.ScMeta = meta.Syscall{
		Name:     "readv",
		Args:     []string{"fd", "iov", "vlen"},
		ArgTypes: []string{"int", "const struct iovec *", "unsigned long"},
	}
	ctx.Args = [6]uint64{4, 0x1000, 1, 0, 0, 0}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindIovec,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   iovecSize,
			CopiedLen: iovecSize,
			ProbeRet:  0,
			Data:      iovecBytes([2]uint64{0x2000, 4}),
		},
	}

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{"4", `[{iov_base="", iov_len=4}]`, "1"}
	assertArgParts(t, "readv zero return", got, want)
}

func TestVmspliceHandlerDecodesSpliceFlags(t *testing.T) {
	ctx := newIovecPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "vmsplice"
	ctx.ScMeta = meta.Syscall{
		Name:     "vmsplice",
		Args:     []string{"fd", "uiov", "nr_segs", "flags"},
		ArgTypes: []string{"int", "const struct iovec *", "long unsigned int", "unsigned int"},
	}
	ctx.Args = [6]uint64{1, 0x1000, 1, 2}
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

	got := (&IoHandler{}).Handle(ctx).ArgParts
	want := []string{"1", "[{iov_base=0x2000, iov_len=3}]", "1", "SPLICE_F_NONBLOCK"}
	assertArgParts(t, "vmsplice flags", got, want)
}

func assertArgParts(t *testing.T, name string, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s arg count = %d, want %d: %#v", name, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s arg %d = %q, want %q; all args %#v", name, i, got[i], want[i], got)
		}
	}
}
