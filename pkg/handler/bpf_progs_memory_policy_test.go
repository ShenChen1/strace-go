package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgLoadAttr(size int) []byte {
	data := make([]byte, size)
	if size >= 24 {
		binary.LittleEndian.PutUint64(data[16:24], 0x3000)
	}
	if size >= 40 {
		binary.LittleEndian.PutUint32(data[28:32], 4)
		binary.LittleEndian.PutUint64(data[32:40], 0x4000)
	}
	if size >= 164 {
		binary.LittleEndian.PutUint64(data[152:160], 0x5000)
		binary.LittleEndian.PutUint32(data[160:164], 3)
	}
	return data
}

func TestBpfProgLoadLicenseDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("GPL\x00ignored"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadAttr(24), 24)
	if !strings.Contains(got, "license=0x3000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadLicenseDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("GPL\x00ignored"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadAttr(24), 24)
	if !strings.Contains(got, "license=0x3000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadLicenseUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 101, UserPtr: 0x3000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("GPL\x00")},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadAttr(24), 24)
	if !strings.Contains(got, `license="GPL"`) {
		t.Fatalf("decodeBpfProgLoad() = %q, want nested license snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadLogBufDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("ok\x00x"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	attr := makeBpfProgLoadAttr(40)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	got := decodeBpfProgLoad(ctx, attr, 40)
	if !strings.Contains(got, "log_buf=0x4000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadLogBufDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("ok\x00x"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	attr := makeBpfProgLoadAttr(40)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	got := decodeBpfProgLoad(ctx, attr, 40)
	if !strings.Contains(got, "log_buf=0x4000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadLogBufUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	attr := makeBpfProgLoadAttr(40)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 102, UserPtr: 0x4000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("log ")},
	}

	got := decodeBpfProgLoad(ctx, attr, 40)
	if !strings.Contains(got, `log_buf="log "...`) {
		t.Fatalf("decodeBpfProgLoad() = %q, want nested log_buf snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadSignatureDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte{1, 2, 3},
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	attr := makeBpfProgLoadAttr(164)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	binary.LittleEndian.PutUint64(attr[32:40], 0)
	got := decodeBpfProgLoad(ctx, attr, 164)
	if !strings.Contains(got, "signature=0x5000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadSignatureDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte{1, 2, 3},
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	attr := makeBpfProgLoadAttr(164)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	binary.LittleEndian.PutUint64(attr[32:40], 0)
	got := decodeBpfProgLoad(ctx, attr, 164)
	if !strings.Contains(got, "signature=0x5000") {
		t.Fatalf("decodeBpfProgLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadSignatureUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	attr := makeBpfProgLoadAttr(164)
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	binary.LittleEndian.PutUint64(attr[32:40], 0)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 103, UserPtr: 0x5000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte{1, 2, 3}},
	}

	got := decodeBpfProgLoad(ctx, attr, 164)
	if !strings.Contains(got, `signature="\x01\x02\x03"`) {
		t.Fatalf("decodeBpfProgLoad() = %q, want nested signature snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
