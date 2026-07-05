package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func keyPolicyContext(name string) *Context {
	return &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: name,
		ScMeta:  meta.Syscall{Name: name},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}
}

func TestAddKeyArgsUsePayloadSections(t *testing.T) {
	ctx := keyPolicyContext("add_key")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 3}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("user\x00")},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("desc\x00")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("abc")},
	}

	assertKeyArg(t, ctx, 0, "type", 0x1000, `"user"`)
	assertKeyArg(t, ctx, 1, "description", 0x2000, `"desc"`)
	assertKeyArg(t, ctx, 2, "payload", 0x3000, `"abc"`)
}

func TestRequestKeyArgsUsePayloadSections(t *testing.T) {
	ctx := keyPolicyContext("request_key")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("user\x00")},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("desc\x00")},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("info\x00")},
	}

	assertKeyArg(t, ctx, 0, "type", 0x1000, `"user"`)
	assertKeyArg(t, ctx, 1, "description", 0x2000, `"desc"`)
	assertKeyArg(t, ctx, 2, "callout_info", 0x3000, `"info"`)
}

func TestAddKeyArgsIgnoreLegacySnapshots(t *testing.T) {
	ctx := keyPolicyContext("add_key")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000, 3}

	assertKeyArg(t, ctx, 0, "type", 0x1000, "0x1000")
	assertKeyArg(t, ctx, 1, "description", 0x2000, "0x2000")
	assertKeyArg(t, ctx, 2, "payload", 0x3000, "0x3000")
}

func TestRequestKeyArgsIgnoreLegacySnapshots(t *testing.T) {
	ctx := keyPolicyContext("request_key")
	ctx.Args = [6]uint64{0x1000, 0x2000, 0x3000}

	assertKeyArg(t, ctx, 0, "type", 0x1000, "0x1000")
	assertKeyArg(t, ctx, 1, "description", 0x2000, "0x2000")
	assertKeyArg(t, ctx, 2, "callout_info", 0x3000, "0x3000")
}

func assertKeyArg(t *testing.T, ctx *Context, argIndex int, argName string, ptr uint64, want string) {
	t.Helper()
	got, ok := decodeKeyArg(ctx, argIndex, argName, ptr)
	if !ok || got != want {
		t.Fatalf("decodeKeyArg(%s) = %q, %v; want %q, true", argName, got, ok, want)
	}
}
