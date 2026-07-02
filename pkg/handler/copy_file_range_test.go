package handler

import (
	"encoding/binary"
	"reflect"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestCopyFileRangeHandlerIgnoresLegacyOffsetSnapshots(t *testing.T) {
	const (
		offInPtr  = 0x7de6fdd44ff8
		offOutPtr = 0x7de6fdd35ff8
	)

	ctx := &Context{
		Pid:       101,
		Tid:       101,
		TargetPid: 101,
		Ret:       -9,
		Args: [6]uint64{
			0xffffffffffffffff,
			offInPtr,
			0xfffffffffffffffe,
			offOutPtr,
			16045691002485145299,
			0,
		},
		ProbeRetEnter: 0,
		StrArgBuf:     make([]byte, BpfMiscArgOffset+16),
		ScMeta: meta.Syscall{
			Name:     "copy_file_range",
			Args:     []string{"fd_in", "off_in", "fd_out", "off_out", "len", "flags"},
			ArgTypes: []string{"int", "loff_t *", "int", "loff_t *", "size_t", "unsigned int"},
		},
		Opts: &cli.Options{},
	}
	ctx.Decoder = event.NewDecoder()
	offIn := make([]byte, 8)
	offOut := make([]byte, 8)
	binary.LittleEndian.PutUint64(offIn, 0xdeadbef1facefed1)
	binary.LittleEndian.PutUint64(offOut, 0xdeadbef2facefed2)
	putSmallSnapshot(ctx, BpfMiscArgOffset, offIn)
	putSmallSnapshot(ctx, BpfMiscArgOffset+8, offOut)

	got := (&CopyFileRangeHandler{}).Handle(ctx).ArgParts
	want := []string{
		"-1",
		"0x7de6fdd44ff8",
		"-2",
		"0x7de6fdd35ff8",
		"16045691002485145299",
		"0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("copy_file_range args = %#v; want %#v", got, want)
	}
}

func TestCopyFileRangeHandlerUsesPayloadStructSections(t *testing.T) {
	const (
		offInPtr  = 0x7de6fdd44ff8
		offOutPtr = 0x7de6fdd35ff8
	)

	ctx := &Context{
		Pid:       101,
		Tid:       101,
		TargetPid: 101,
		Ret:       -9,
		Args:      [6]uint64{4, offInPtr, 5, offOutPtr, 99, 0},
		ScMeta: meta.Syscall{
			Name:     "copy_file_range",
			Args:     []string{"fd_in", "off_in", "fd_out", "off_out", "len", "flags"},
			ArgTypes: []string{"int", "loff_t *", "int", "loff_t *", "size_t", "unsigned int"},
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: copyFileRangeOffsetData(11)},
			{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 3, ProbeRet: 0, Data: copyFileRangeOffsetData(22)},
		},
	}

	got := (&CopyFileRangeHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "[11]", "5", "[22]", "99", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("copy_file_range args = %#v; want %#v", got, want)
	}
}

func TestCopyFileRangeHandlerDoesNotReadMissingOffsetSnapshot(t *testing.T) {
	const (
		offInPtr  = 0x7de6fdd44ff8
		offOutPtr = 0x7de6fdd35ff8
	)
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(7)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           101,
		Tid:           101,
		TargetPid:     101,
		Args:          [6]uint64{4, offInPtr, 5, offOutPtr, 99, 0},
		ProbeRetEnter: -1,
		StrArgBuf:     make([]byte, BpfMiscArgOffset+16),
		ScMeta: meta.Syscall{
			Name:     "copy_file_range",
			Args:     []string{"fd_in", "off_in", "fd_out", "off_out", "len", "flags"},
			ArgTypes: []string{"int", "loff_t *", "int", "loff_t *", "size_t", "unsigned int"},
		},
		Decoder: decoder,
		Opts:    &cli.Options{},
	}

	got := (&CopyFileRangeHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "0x7de6fdd44ff8", "5", "0x7de6fdd35ff8", "99", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("copy_file_range args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func copyFileRangeOffsetData(value uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
