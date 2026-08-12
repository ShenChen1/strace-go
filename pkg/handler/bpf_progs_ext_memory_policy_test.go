package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfObjPinAttr(pathAddr uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data[0:8], pathAddr)
	return data
}

func makeBpfRawTracepointAttr(nameAddr uint64) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint64(data[0:8], nameAddr)
	return data
}

func makeBpfBtfLoadAttr(btfAddr uint64, btfSize uint32) []byte {
	data := make([]byte, 28)
	binary.LittleEndian.PutUint64(data[0:8], btfAddr)
	binary.LittleEndian.PutUint32(data[16:20], btfSize)
	return data
}

func TestBpfObjPinDoesNotReadPathWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("/sys/fs/bpf/test\x00"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfObjPin(ctx, makeBpfObjPinAttr(0x3000), 8)
	if !strings.Contains(got, "pathname=0x3000") {
		t.Fatalf("decodeBpfObjPin() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfObjPinDoesNotUseLegacyPathFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("/sys/fs/bpf/test\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfObjPin(ctx, makeBpfObjPinAttr(0x3000), 8)
	if !strings.Contains(got, "pathname=0x3000") {
		t.Fatalf("decodeBpfObjPin() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfObjPinUsesNestedPathPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionIn,
			ArgIndex:  104,
			UserPtr:   0x3000,
			UserLen:   17,
			CopiedLen: 17,
			ProbeRet:  0,
			Data:      []byte("/sys/fs/bpf/test\x00"),
		},
	}

	got := decodeBpfObjPin(ctx, makeBpfObjPinAttr(0x3000), 8)
	if !strings.Contains(got, `pathname="/sys/fs/bpf/test"`) {
		t.Fatalf("decodeBpfObjPin() = %q, want nested pathname snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfRawTracepointDoesNotReadNameWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("sched_switch\x00"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfRawTracepointOpen(ctx, makeBpfRawTracepointAttr(0x4000), 12)
	if !strings.Contains(got, "name=0x4000") {
		t.Fatalf("decodeBpfRawTracepointOpen() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfRawTracepointDoesNotUseLegacyNameFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("sched_switch\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfRawTracepointOpen(ctx, makeBpfRawTracepointAttr(0x4000), 12)
	if !strings.Contains(got, "name=0x4000") {
		t.Fatalf("decodeBpfRawTracepointOpen() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfRawTracepointUsesNestedNamePayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	cliOptionsForTest(ctx).StringLimit = 32
	name := []byte("0123456789qwertyuiop0123456789qwerty\x00")
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionIn,
			ArgIndex:  105,
			UserPtr:   0x4000,
			UserLen:   uint32(len(name)),
			CopiedLen: uint32(len(name)),
			ProbeRet:  0,
			Data:      name,
		},
	}

	got := decodeBpfRawTracepointOpen(ctx, makeBpfRawTracepointAttr(0x4000), 24)
	if !strings.Contains(got, `name="0123456789qwertyuiop0123456789qw"...`) {
		t.Fatalf("decodeBpfRawTracepointOpen() = %q, want nested name snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfBtfLoadDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfBtfLoad(ctx, makeBpfBtfLoadAttr(0x5000, 9), 28)
	if !strings.Contains(got, "btf=0x5000") {
		t.Fatalf("decodeBpfBtfLoad() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfBtfLoadDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfBtfLoad(ctx, makeBpfBtfLoadAttr(0x5000, 9), 28)
	if !strings.Contains(got, "btf=0x5000") {
		t.Fatalf("decodeBpfBtfLoad() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfBtfLoadUsesNestedBtfPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  106,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("bPf\x00daTum"),
		},
	}

	got := decodeBpfBtfLoad(ctx, makeBpfBtfLoadAttr(0x5000, 9), 28)
	if !strings.Contains(got, `btf="bPf\0daTum"`) {
		t.Fatalf("decodeBpfBtfLoad() = %q, want nested btf bytes snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
