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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}
