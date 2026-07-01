package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func xattrPolicyContext(name string) *Context {
	return &Context{
		Pid:     1234,
		Tid:     1234,
		ScMeta:  meta.Syscall{Name: name},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}
}

func TestXattrNameUsesPayloadStringSection(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("user.k\x00")},
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "name", 0x2000, &res)
	if !ok || got != `"user.k"` {
		t.Fatalf("decodeCharPointer(xattr name) = %q, %v; want payload string", got, ok)
	}
}

func TestSetxattrValueUsesPayloadBytesSection(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 3}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("abc")},
	}

	got, ok := decodeXattrValueArg(ctx, 2, "const void *", "value", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != `"abc"` {
		t.Fatalf("decodeXattrValueArg(setxattr) = %q, %v; want payload bytes", got, ok)
	}
}

func TestGetxattrValueUsesPayloadBytesSection(t *testing.T) {
	ctx := xattrPolicyContext("getxattr")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 8}
	ctx.Ret = 4
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("data")},
	}

	got, ok := decodeXattrValueArg(ctx, 2, "void *", "value", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != `"data"` {
		t.Fatalf("decodeXattrValueArg(getxattr) = %q, %v; want payload bytes", got, ok)
	}
}

func TestListxattrValueUsesPayloadBytesSection(t *testing.T) {
	ctx := xattrPolicyContext("listxattr")
	ctx.Args = [6]uint64{0x1000, 0x3000, 6}
	ctx.Ret = 6
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("names1")},
	}

	got, ok := decodeXattrValueArg(ctx, 1, "char *", "list", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != `"names1"` {
		t.Fatalf("decodeXattrValueArg(listxattr) = %q, %v; want payload bytes", got, ok)
	}
}
