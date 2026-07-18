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
		Opts:          &cli.Options{},
	}
	ctx.Decoder = event.NewDecoder()
	return ctx
}

func TestSendfileHandlerUsesPayloadStructSections(t *testing.T) {
	ctx := sendfileContext(35499)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: sendfileOffsetData(10)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: sendfileOffsetData(20)},
	}

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "[10 => 20]", "35499"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
}

func TestSendfileHandlerUsesPayloadStructEnterOnlyOnError(t *testing.T) {
	ctx := sendfileContext(-22)
	ctx.Args[3] = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: sendfileOffsetData(0xcafef00dfacefeed)},
	}

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "[14627392582579060461]", "1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
}

func TestSendfileHandlerIgnoresLegacyOffsetSnapshots(t *testing.T) {
	ctx := sendfileContext(35499)

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "0x7591c4437ff8", "35499"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
}

func TestSendfileHandlerDoesNotReadMissingOffsetSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(7)}
	decoder := event.NewDecoder()
	ctx := sendfileContext(1)
	ctx.ProbeRetEnter = -1
	ctx.ProbeRetExit = -1
	ctx.Decoder = decoder

	got := (&SendfileHandler{}).Handle(ctx).ArgParts
	want := []string{"4", "5", "0x7591c4437ff8", "35499"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sendfile args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func sendfileOffsetData(value uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
