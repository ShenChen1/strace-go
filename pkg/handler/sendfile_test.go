package handler

import (
	"encoding/binary"
	"reflect"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func sendfileContext(ret int64) *Context {
	ctx := &Context{
		Pid:       101,
		Tid:       101,
		TargetPid: 101,
		Ret:       ret,
		Args:      [6]uint64{4, 5, 0x7591c4437ff8, 35499},
		ScMeta: meta.Syscall{
			Name:     "sendfile",
			Args:     []string{"out_fd", "in_fd", "offset", "count"},
			ArgTypes: []string{"int", "int", "off_t *", "size_t"},
		},
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
		StrArgBuf:     make([]byte, sendfileOffsetExitOffset+8),
		MemReader:     mapMemoryReader{},
		Opts:          &cli.Options{},
	}
	ctx.Decoder = event.NewDecoder(ctx.MemReader)
	return ctx
}

func TestSendfileHandlerDecodesUpdatedOffset(t *testing.T) {
	ctx := sendfileContext(35499)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[sendfileOffsetEnterOffset:], 0)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[sendfileOffsetExitOffset:], 35499)

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "[0] => [35499]", "35499"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
}

func TestSendfileHandlerDecodesUnchangedOffset(t *testing.T) {
	ctx := sendfileContext(-22)
	ctx.Args[3] = 1
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[sendfileOffsetEnterOffset:], 0xcafef00dfacefeed)

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "[14627392582579060461]", "1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
}
