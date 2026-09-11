package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeClone3Data(flags uint64) []byte {
	data := make([]byte, 88)
	binary.LittleEndian.PutUint64(data[0:8], flags)
	return data
}

func makeUint32Slice(values ...uint32) []byte {
	data := make([]byte, len(values)*4)
	for i, v := range values {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], v)
	}
	return data
}

func newClone3PolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "clone3",
		Args:          [6]uint64{0x1000, 88},
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
		ScMeta: meta.Syscall{
			Name:     "clone3",
			Args:     []string{"uargs", "size"},
			ArgTypes: []string{"struct clone_args *", "size_t"},
		},
	}
}

func TestDecodeStringArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: pointerBytes(0x2000)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Decoder: decoder,
		Opts:    &cli.Options{StringLimit: 32},
		ScMeta:  meta.Syscall{Name: "execve"},
	}

	got := decodeStringArray(ctx, 0x1000, "argv")
	if got != "0x1000" {
		t.Fatalf("decodeStringArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestClone3DoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeClone3Data(0)}
	decoder := event.NewDecoder()
	ctx := newClone3PolicyContext(reader, decoder)

	got := (&ProcessHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[0] != "0x1000" {
		t.Fatalf("clone3 args = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestClone3IgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeClone3Data(0)}
	ctx := newClone3PolicyContext(reader, event.NewDecoder())
	ctx.ProbeRetEnter = 0

	got := (&ProcessHandler{}).Handle(ctx)
	if got.ArgParts[0] != "0x1000" {
		t.Fatalf("clone3 args = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestClone3UsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeClone3Data(0)}
	ctx := newClone3PolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: makeClone3Data(0)},
	}

	got := (&ProcessHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[0], "flags=0") {
		t.Fatalf("clone3 args = %q", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestClone3SetTidDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint32Slice(11, 22)}
	decoder := event.NewDecoder()
	ctx := newClone3PolicyContext(reader, decoder)
	data := makeClone3Data(0)
	binary.LittleEndian.PutUint64(data[64:72], 0x3000)
	binary.LittleEndian.PutUint64(data[72:80], 2)

	got := (&ProcessHandler{}).decodeCloneArgsSetTid(ctx, data, 88)
	want := []string{"set_tid=0x3000, set_tid_size=2"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("decodeCloneArgsSetTid() = %#v, want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestClone3SetTidUsesNestedPayloadSection(t *testing.T) {
	const setTidPtr = 0x3000
	ctx := newClone3PolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	data := makeClone3Data(0)
	binary.LittleEndian.PutUint64(data[64:72], setTidPtr)
	binary.LittleEndian.PutUint64(data[72:80], 2)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: data},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: clone3SetTidPayloadArgIndex, UserPtr: setTidPtr, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: makeUint32Slice(11, 22)},
	}

	got := (&ProcessHandler{}).Handle(ctx)
	want := "{flags=0, exit_signal=0, stack=NULL, stack_size=0, set_tid=[11, 22], set_tid_size=2}"
	if got.ArgParts[0] != want {
		t.Fatalf("clone3 args = %q, want %q", got.ArgParts[0], want)
	}
}

func TestClone3PostDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint32Slice(777)}
	decoder := event.NewDecoder()
	ctx := newClone3PolicyContext(reader, decoder)
	ctx.Ret = 123
	data := makeClone3Data(0x00100000)
	binary.LittleEndian.PutUint64(data[24:32], 0x4000)

	got := (&ProcessHandler{}).decodeCloneArgsPost(ctx, data, 88)
	if got != "" {
		t.Fatalf("decodeCloneArgsPost() = %q, want empty fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
