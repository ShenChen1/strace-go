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
		SysName: name,
		ScMeta:  meta.Syscall{Name: name},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}
}

func putXattrLegacySnapshot(ctx *Context, offset int, data []byte) {
	end := offset + len(data)
	if len(ctx.StrArgBuf) < end {
		buf := make([]byte, end)
		copy(buf, ctx.StrArgBuf)
		ctx.StrArgBuf = buf
	}
	copy(ctx.StrArgBuf[offset:end], data)
	if ctx.DataLen < uint32(end) {
		ctx.DataLen = uint32(end)
	}
}

func TestXattrPathUsesPayloadStringSection(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("/tmp/a\x00")},
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "path", 0x1000, &res)
	if !ok || got != `"/tmp/a"` {
		t.Fatalf("decodeCharPointer(xattr path) = %q, %v; want payload string", got, ok)
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

func TestXattrPathIgnoresLegacyStringSnapshot(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	putXattrLegacySnapshot(ctx, 0, []byte("/tmp/a\x00"))

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "path", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeCharPointer(xattr path without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestXattrNameIgnoresLegacyStringSnapshot(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	putXattrLegacySnapshot(ctx, 512, []byte("user.k\x00"))

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "name", 0x2000, &res)
	if !ok || got != "0x2000" {
		t.Fatalf("decodeCharPointer(xattr name without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestSetxattrValueIgnoresLegacyEnterSnapshot(t *testing.T) {
	ctx := xattrPolicyContext("setxattr")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 3}
	putXattrLegacySnapshot(ctx, 768, []byte("abc"))

	got, ok := decodeXattrValueArg(ctx, 2, "const void *", "value", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeXattrValueArg(setxattr without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestGetxattrValueIgnoresLegacyExitSnapshot(t *testing.T) {
	ctx := xattrPolicyContext("getxattr")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 8}
	ctx.Ret = 4
	putXattrLegacySnapshot(ctx, 768, []byte("data"))

	got, ok := decodeXattrValueArg(ctx, 2, "void *", "value", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeXattrValueArg(getxattr without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestListxattrValueIgnoresLegacyExitSnapshot(t *testing.T) {
	ctx := xattrPolicyContext("listxattr")
	ctx.Args = [6]uint64{0x1000, 0x3000, 6}
	ctx.Ret = 6
	putXattrLegacySnapshot(ctx, 512, []byte("names1"))

	got, ok := decodeXattrValueArg(ctx, 1, "char *", "list", 0x3000, ctx.Opts.StringLimit)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeXattrValueArg(listxattr without section) = %q, %v; want pointer fallback", got, ok)
	}
}
