package handler

import (
	"encoding/binary"
	"reflect"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func processMadviseContext() *Context {
	return &Context{
		Pid:       101,
		Tid:       101,
		TargetPid: 101,
		Ret:       -22,
		ScMeta: meta.Syscall{
			Name:     "process_madvise",
			Args:     []string{"pidfd", "vec", "vlen", "behavior", "flags"},
			ArgTypes: []string{"int", "const struct iovec *", "size_t", "int", "unsigned int"},
		},
		Opts: &cli.Options{},
		Meta: meta.NewCatalog("abbrev"),
	}
}

func iovecBytes(entries ...[2]uint64) []byte {
	data := make([]byte, len(entries)*16)
	for i, entry := range entries {
		binary.LittleEndian.PutUint64(data[i*16:i*16+8], entry[0])
		binary.LittleEndian.PutUint64(data[i*16+8:i*16+16], entry[1])
	}
	return data
}

func TestProcessMadviseHandlerIgnoresLegacyEnterSnapshot(t *testing.T) {
	const vec = 0x7000
	ctx := processMadviseContext()
	ctx.Args = [6]uint64{0, vec, 2, 0, 0xffffffff}
	ctx.ProbeRetEnter = 0

	got := (&ProcessMadviseHandler{}).Handle(ctx).ArgParts
	want := []string{
		"0",
		"0x7000",
		"2",
		"MADV_NORMAL",
		"0xffffffff",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("process_madvise args = %#v; want %#v", got, want)
	}
}

func TestProcessMadviseHandlerUsesPayloadIovecSection(t *testing.T) {
	const vec = 0x7000
	iovs := iovecBytes(
		[2]uint64{0x8786858483828180, 10344361028892658056},
		[2]uint64{0x9796959493929190, 11501803794301884824},
	)
	ctx := processMadviseContext()
	ctx.Args = [6]uint64{0, vec, 1, 0, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: iovs},
	}

	got := (&ProcessMadviseHandler{}).Handle(ctx).ArgParts
	want := []string{
		"0",
		"[{iov_base=0x8786858483828180, iov_len=10344361028892658056}]",
		"1",
		"MADV_NORMAL",
		"0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("process_madvise payload args = %#v; want %#v", got, want)
	}
}

func TestProcessMadviseHandlerNullAndEmptyIov(t *testing.T) {
	ctx := processMadviseContext()
	ctx.Args = [6]uint64{0xffffffff, 0, 0xdeadbeefdeadbeef, 20, 0}
	got := (&ProcessMadviseHandler{}).Handle(ctx).ArgParts
	want := []string{"-1", "NULL", "16045690984833335023", "MADV_COLD", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("process_madvise NULL args = %#v; want %#v", got, want)
	}

	ctx.Args = [6]uint64{0, 0x7000, 0, 21, 0xcafef00d}
	got = (&ProcessMadviseHandler{}).Handle(ctx).ArgParts
	want = []string{"0", "[]", "0", "MADV_PAGEOUT", "0xcafef00d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("process_madvise empty iov args = %#v; want %#v", got, want)
	}
}

func TestProcessMadviseHandlerShortIovReadShowsNextAddress(t *testing.T) {
	const vec = 0x7fff0
	iovs := iovecBytes([2]uint64{0x9796959493929190, 11501803794301884824})
	ctx := processMadviseContext()
	ctx.Args = [6]uint64{0xffffffff, vec, 2, 0xdeadc0de, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: iovs},
	}

	got := (&ProcessMadviseHandler{}).Handle(ctx).ArgParts
	want := []string{
		"-1",
		"[{iov_base=0x9796959493929190, iov_len=11501803794301884824}, ... /* 0x80000 */]",
		"2",
		"0xdeadc0de /* MADV_??? */",
		"0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("process_madvise short iov args = %#v; want %#v", got, want)
	}
}
