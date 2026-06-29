package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func newIovecPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "readv",
		Decoder: decoder,
		Opts:    &cli.Options{StringLimit: 32},
	}
}

func TestDecodeIovecArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("DecodeIovecArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = make([]byte, iovecSize)
	putSmallSnapshot(ctx, BpfEnterArgOffset, iovecBytes([2]uint64{0x2000, 3}))

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if got != "[{iov_base=0x2000, iov_len=3}]" {
		t.Fatalf("DecodeIovecArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayUsesPartialEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := newIovecPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = make([]byte, iovecSize)
	putSmallSnapshot(ctx, BpfEnterArgOffset, iovecBytes([2]uint64{0x2000, 3}))

	got := DecodeIovecArray(ctx, 1, 0x1000, 2)
	if got != "[{iov_base=0x2000, iov_len=3}, ...]" {
		t.Fatalf("DecodeIovecArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeIovecArrayDoesNotUseLegacyPayloadFallback(t *testing.T) {
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "writev",
		ProbeRetEnter: 0,
		StrArgBuf:     make([]byte, iovecSize),
		Decoder:       event.NewDecoder(),
		Opts:          &cli.Options{StringLimit: 32},
	}
	putSmallSnapshot(ctx, BpfEnterArgOffset, iovecBytes([2]uint64{0x2000, 3}))

	got := DecodeIovecArray(ctx, 1, 0x1000, 1)
	if strings.Contains(got, `"abc"`) || !strings.Contains(got, `iov_base=0x2000`) {
		t.Fatalf("DecodeIovecArray() = %q", got)
	}
}

func TestProcessMadviseIovecDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Decoder: decoder,
	}

	got := formatProcessMadviseIovec(ctx, 0x1000, 1)
	if got != "0x1000" {
		t.Fatalf("formatProcessMadviseIovec() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestProcessMadviseIovecUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: iovecBytes([2]uint64{0x2000, 3})}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		ProbeRetEnter: 0,
		Decoder:       decoder,
		StrArgBuf:     make([]byte, iovecSize),
	}
	putSmallSnapshot(ctx, BpfEnterArgOffset, iovecBytes([2]uint64{0x2000, 3}))

	got := formatProcessMadviseIovec(ctx, 0x1000, 1)
	if got != "[{iov_base=0x2000, iov_len=3}]" {
		t.Fatalf("formatProcessMadviseIovec() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
