package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestDecodeWriteDumpDoesNotUseTraceeMemoryBeyondPayloadPrefix(t *testing.T) {
	data := make([]byte, 0x300)
	for i := range data {
		data[i] = byte(i)
	}
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args:      [6]uint64{1, 0x1000, uint64(len(data))},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		ProbeRetEnter: 0,
		Ret:           int64(len(data)),
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   uint32(len(data)),
				CopiedLen: 512,
				ProbeRet:  0,
				Data:      data[:512],
			},
		},
		Opts: &cli.Options{
			StringLimit:   32,
			TraceWriteFDs: map[int32]bool{1: true},
		},
	}
	ctx.Decoder = event.NewDecoder()

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x1000, &res)
	if !ok {
		t.Fatal("decodeBufferArg did not handle write buffer")
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("write buffer summary = %q, want abbreviated string", got)
	}
	if strings.Contains(res.HexDumpStr, "00200") {
		t.Fatalf("hexdump unexpectedly included data beyond BPF prefix:\n%s", res.HexDumpStr)
	}
	if !strings.Contains(res.HexDumpStr, "Cannot fetch 256 bytes") {
		t.Fatalf("hexdump did not report missing bytes:\n%s", res.HexDumpStr)
	}
}

func TestDecodeWriteBufferIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args:      [6]uint64{1, 0x1000, 3},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		ProbeRetEnter: 0,
		Opts:          &cli.Options{StringLimit: 32},
		Decoder:       event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "buf", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeCharPointer(write) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeReadBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid: 101,
		Tid: 102,
		Args: [6]uint64{
			3,
			0x2000,
			32,
		},
		Ret: 5,
		ScMeta: meta.Syscall{
			Name:     "read",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionOut,
				ArgIndex:  1,
				UserPtr:   0x2000,
				UserLen:   5,
				CopiedLen: 5,
				ProbeRet:  0,
				Data:      []byte("hello"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x2000, &res)
	if !ok || got != `"hello"` {
		t.Fatalf("decodeBufferArg(read) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeWriteBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args: [6]uint64{
			1,
			0x1000,
			5,
		},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   5,
				CopiedLen: 5,
				ProbeRet:  0,
				Data:      []byte("world"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x1000, &res)
	if !ok || got != `"world"` {
		t.Fatalf("decodeBufferArg(write) = %q, %v; want payload section", got, ok)
	}
}
