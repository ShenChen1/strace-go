package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func newFsconfigBinaryContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	buf := make([]byte, 4353)
	copy(buf[0:257], []byte("blob\x00"))
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "fsconfig",
		Args:          [6]uint64{3, 2, 0x1000, 0x2000, 3},
		ProbeRetEnter: 0,
		Decoder:       decoder,
		Opts:          &cli.Options{StringLimit: 32},
		StrArgBuf:     buf,
	}
}

func TestFsconfigBinaryDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{1, 2, 3}}
	decoder := event.NewDecoder()
	ctx := newFsconfigBinaryContext(reader, decoder)

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x2000" {
		t.Fatalf("fsconfig value = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFsconfigBinaryUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{1, 2, 3}}
	ctx := newFsconfigBinaryContext(reader, event.NewDecoder())
	copy(ctx.StrArgBuf[257:260], []byte{1, 2, 3})
	ctx.DataLen = 260

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[3] == "0x2000" {
		t.Fatalf("fsconfig value = %q, want decoded data", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func newGetdentsContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "getdents64",
		Args:         [6]uint64{3, 0x3000, 512},
		Ret:          16,
		ProbeRetExit: -1,
		Decoder:      decoder,
		ScMeta: meta.Syscall{
			Args:     []string{"fd", "dirent", "count"},
			ArgTypes: []string{"unsigned int", "struct linux_dirent64 *", "unsigned int"},
		},
		StrArgBuf: make([]byte, 512),
	}
}

func TestGetdentsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: make([]byte, 512)}
	decoder := event.NewDecoder()
	ctx := newGetdentsContext(reader, decoder)

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 3 {
		t.Fatalf("ArgParts len = %d, want 3", len(got.ArgParts))
	}
	if got.ArgParts[1] != "{...}" {
		t.Fatalf("getdents dirent = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestGetdentsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: make([]byte, 512)}
	ctx := newGetdentsContext(reader, event.NewDecoder())

	(&FsHandler{}).Handle(ctx)
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
