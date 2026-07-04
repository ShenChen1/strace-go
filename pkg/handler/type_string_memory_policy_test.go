package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestDecodeGenericCharPointerUsesPayloadStringSection(t *testing.T) {
	ctx := genericStringContext()
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1000,
			UserLen:   7,
			CopiedLen: 7,
			ProbeRet:  0,
			Data:      []byte("worker\x00"),
		},
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "name", 0x1000, &res)
	if !ok || got != `"worker"` {
		t.Fatalf("decodeCharPointer(generic string) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeGenericCharPointerIgnoresLegacyStringSnapshot(t *testing.T) {
	ctx := genericStringContext()
	ctx.StrArgBuf = make([]byte, 512)
	ctx.DataLen = uint32(len("legacy") + 1)
	ctx.ProbeRetEnter = 0
	copy(ctx.StrArgBuf, []byte("legacy\x00"))

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "name", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeCharPointer(generic legacy snapshot) = %q, %v; want pointer fallback", got, ok)
	}
}

func genericStringContext() *Context {
	return &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "sethostname",
			Args:     []string{"name", "len"},
			ArgTypes: []string{"const char *", "size_t"},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}
}
