package handler

import (
	"encoding/binary"
	"reflect"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestCopyFileRangeHandlerDecodesEnterOffsets(t *testing.T) {
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
		StrArgBuf:     make([]byte, copyFileRangeOffOutOffset+8),
		ScMeta: meta.Syscall{
			Name:     "copy_file_range",
			Args:     []string{"fd_in", "off_in", "fd_out", "off_out", "len", "flags"},
			ArgTypes: []string{"int", "loff_t *", "int", "loff_t *", "size_t", "unsigned int"},
		},
		MemReader: mapMemoryReader{},
		Opts:      &cli.Options{},
	}
	ctx.Decoder = event.NewDecoder(ctx.MemReader)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[copyFileRangeOffInOffset:], 0xdeadbef1facefed1)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[copyFileRangeOffOutOffset:], 0xdeadbef2facefed2)

	got := (&CopyFileRangeHandler{}).Handle(ctx).ArgParts
	want := []string{
		"-1",
		"[-2401053079814340911]",
		"-2",
		"[-2401053075519373614]",
		"16045691002485145299",
		"0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("copy_file_range args = %#v; want %#v", got, want)
	}
}
