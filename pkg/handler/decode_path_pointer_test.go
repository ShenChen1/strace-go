package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestDecodePathUsesPayloadStringSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "openat",
			Args:     []string{"dfd", "filename", "flags"},
			ArgTypes: []string{"int", "const char *", "int"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x3000,
				UserLen:   13,
				CopiedLen: 13,
				ProbeRet:  0,
				Data:      []byte("/tmp/section\x00"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "filename", 0x3000, &res)
	if !ok || got != `"/tmp/section"` {
		t.Fatalf("decodeCharPointer(path) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodePathIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "openat",
			Args:     []string{"dfd", "filename", "flags"},
			ArgTypes: []string{"int", "const char *", "int"},
		},
		ProbeRetEnter: 0,
		Opts:          &cli.Options{StringLimit: 32},
		Decoder:       event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "filename", 0x3000, &res)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeCharPointer(path without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeMemfdNameUsesPayloadStringSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "memfd_create",
			Args:     []string{"uname", "flags"},
			ArgTypes: []string{"const char *", "unsigned int"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  0,
				UserPtr:   0x3000,
				UserLen:   13,
				CopiedLen: 13,
				ProbeRet:  0,
				Data:      []byte("section-name\x00"),
			},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "uname", 0x3000, &res)
	if !ok || got != `"section-name"` {
		t.Fatalf("decodeCharPointer(memfd_create) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeMemfdNameIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "memfd_create",
			Args:     []string{"uname", "flags"},
			ArgTypes: []string{"const char *", "unsigned int"},
		},
		ProbeRetEnter: 0,
		Opts:          &cli.Options{StringLimit: 32},
		Decoder:       event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "uname", 0x3000, &res)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeCharPointer(memfd_create without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeReadlinkBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Ret:       6,
		ScMeta: meta.Syscall{
			Name:     "readlink",
			Args:     []string{"path", "buf", "bufsiz"},
			ArgTypes: []string{"const char *", "char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionOut,
				ArgIndex:  1,
				UserPtr:   0x3000,
				UserLen:   6,
				CopiedLen: 6,
				ProbeRet:  0,
				Data:      []byte("target"),
			},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}

	got, ok := decodeReadlinkBuffer(ctx, 1, 0x3000)
	if !ok || got != `"target"` {
		t.Fatalf("decodeReadlinkBuffer() = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeReadlinkBufferIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Ret:       6,
		ScMeta: meta.Syscall{
			Name:     "readlink",
			Args:     []string{"path", "buf", "bufsiz"},
			ArgTypes: []string{"const char *", "char *", "size_t"},
		},
		ProbeRetExit: 0,
		Opts:         &cli.Options{StringLimit: 32},
		Decoder:      event.NewDecoder(),
	}

	got, ok := decodeReadlinkBuffer(ctx, 1, 0x3000)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeReadlinkBuffer() = %q, %v; want pointer fallback", got, ok)
	}
}
