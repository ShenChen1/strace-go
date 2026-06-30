package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestDecodeRenameArgsUsePayloadStringSections(t *testing.T) {
	ctx := &Context{
		Pid: 101,
		Tid: 102,
		Args: [6]uint64{
			0x1000,
			0x2000,
		},
		ScMeta: meta.Syscall{
			Name:     "rename",
			Args:     []string{"oldpath", "newpath"},
			ArgTypes: []string{"const char *", "const char *"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  0,
				UserPtr:   0x1000,
				UserLen:   4,
				CopiedLen: 4,
				ProbeRet:  0,
				Data:      []byte("old\x00"),
			},
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x2000,
				UserLen:   4,
				CopiedLen: 4,
				ProbeRet:  0,
				Data:      []byte("new\x00"),
			},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}
	res := Result{}

	oldPath, ok := decodeCharPointer(ctx, 0, "const char *", "oldpath", 0x1000, &res)
	if !ok || oldPath != `"old"` {
		t.Fatalf("decode old path = %q, %v", oldPath, ok)
	}
	newPath, ok := decodeCharPointer(ctx, 1, "const char *", "newpath", 0x2000, &res)
	if !ok || newPath != `"new"` {
		t.Fatalf("decode new path = %q, %v", newPath, ok)
	}
}

func TestDecodeRenameArgFallsBackToPointerWithoutSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:     101,
		Tid:     102,
		Args:    [6]uint64{0x1000, 0x2000},
		ScMeta:  meta.Syscall{Name: "rename"},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}

	got, ok := decodeRenArg(ctx, 0, 0x1000)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeRenArg fallback = %q, %v; want pointer", got, ok)
	}
}
