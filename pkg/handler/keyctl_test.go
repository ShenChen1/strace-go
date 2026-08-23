package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestKeyctlHandlerConsumesOperationSpecificSnapshots(t *testing.T) {
	ctx := &Context{
		SysName: "keyctl",
		ScMeta: meta.Syscall{
			Name:     "keyctl",
			Args:     []string{"option", "arg2", "arg3", "arg4", "arg5"},
			ArgTypes: []string{"int", "unsigned long", "unsigned long", "unsigned long", "unsigned long"},
		},
		Args: [6]uint64{11, 0x1000, 0x2000, 64},
		Ret:  18,
		Meta: meta.NewCatalog("abbrev"),
		Opts: &cli.Options{StringLimit: 32},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: []byte("ebpf-keyctl-update")},
		},
	}
	got := (&KeyctlHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 || got.ArgParts[2] != "\"ebpf-keyctl-update\"" {
		t.Fatalf("keyctl read args = %#v, want snapshot payload", got.ArgParts)
	}

	ctx.Args[0] = 31
	ctx.Args[1] = 0x2000
	ctx.Args[2] = 2
	ctx.Ret = 2
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: []byte{0xff, 0x07}},
	}
	got = (&KeyctlHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 || got.ArgParts[1] != `"\377\7"` {
		t.Fatalf("keyctl capabilities args = %#v, want byte snapshot", got.ArgParts)
	}
}

func TestKeyctlHandlerKeepsRejectArgumentsScalar(t *testing.T) {
	ctx := &Context{
		SysName: "keyctl",
		ScMeta: meta.Syscall{
			Name:     "keyctl",
			Args:     []string{"option", "key", "timeout", "error", "keyring"},
			ArgTypes: []string{"int", "unsigned long", "unsigned long", "unsigned long", "unsigned long"},
		},
		Args: [6]uint64{keyctlReject, 0x1000, 30, 0x2000, 0x3000},
		Ret:  -1,
		Meta: meta.NewCatalog("abbrev"),
		Opts: &cli.Options{StringLimit: 32},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: []byte("must-not-be-consumed")},
		},
	}

	got := (&KeyctlHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 || got.ArgParts[2] != "0x1e" {
		t.Fatalf("keyctl reject args = %#v, want scalar timeout", got.ArgParts)
	}
}
