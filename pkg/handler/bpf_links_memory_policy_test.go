package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfU64Array(vals ...uint64) []byte {
	data := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(data[i*8:(i+1)*8], v)
	}
	return data
}

func makeBpfU32Array(vals ...uint32) []byte {
	data := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(data[i*4:(i+1)*4], v)
	}
	return data
}

func TestBpfLinkSymsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfU64Array(0x2000),
		0x2000: []byte("foo\x00"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeSymsArray(ctx, 0x1000, 1)
	if got != "syms=0x1000" {
		t.Fatalf("decodeSymsArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkSymsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfU64Array(0x2000),
		0x2000: []byte("foo\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeSymsArray(ctx, 0x1000, 1)
	if got != "syms=0x1000" {
		t.Fatalf("decodeSymsArray() = %q", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkU64ArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBpfU64Array(0, 1, 0xbadc0ded),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeU64Array(ctx, "addrs", 0x3000, 3)
	if got != "addrs=0x3000" {
		t.Fatalf("decodeU64Array() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkU64ArrayDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBpfU64Array(0, 1, 0xbadc0ded),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeU64Array(ctx, "addrs", 0x3000, 3)
	if got != "addrs=0x3000" {
		t.Fatalf("decodeU64Array() = %q", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkIterInfoDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: makeBpfU32Array(42),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfIterInfo(ctx, 0x4000, 1)
	if got != "iter_info=0x4000" {
		t.Fatalf("decodeBpfIterInfo() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkIterInfoDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: makeBpfU32Array(42),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfIterInfo(ctx, 0x4000, 1)
	if got != "iter_info=0x4000" {
		t.Fatalf("decodeBpfIterInfo() = %q", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkStreamBufDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != "0x5000" {
		t.Fatalf("decodeStreamBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfLinkStreamBufDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != "0x5000" {
		t.Fatalf("decodeStreamBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}
