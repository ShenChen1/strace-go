package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgLoadFuncInfoAttrForTest(ptr uint64, recSize, count uint32) []byte {
	data := make([]byte, 168)
	binary.LittleEndian.PutUint32(data[76:80], recSize)
	binary.LittleEndian.PutUint64(data[80:88], ptr)
	binary.LittleEndian.PutUint32(data[88:92], count)
	return data
}

func makeBpfFuncInfoDataForTest(records ...[2]uint32) []byte {
	data := make([]byte, len(records)*8)
	for i, record := range records {
		binary.LittleEndian.PutUint32(data[i*8:i*8+4], record[0])
		binary.LittleEndian.PutUint32(data[i*8+4:i*8+8], record[1])
	}
	return data
}

func TestBpfProgLoadFuncInfoUsesNestedPayloadSection(t *testing.T) {
	data := makeBpfFuncInfoDataForTest([2]uint32{0, 0x1234}, [2]uint32{8, 0x5678})
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  142,
		UserPtr:   0x7000,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFuncInfoAttrForTest(0x7000, 8, 2), 168)
	if !strings.Contains(got, "func_info=[{insn_off=0, type_id=4660}, {insn_off=8, type_id=22136}]") {
		t.Fatalf("decodeBpfProgLoad() = %q, want func_info records", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFuncInfoPreservesBoundedPrefix(t *testing.T) {
	data := makeBpfFuncInfoDataForTest([2]uint32{0, 0x1234}, [2]uint32{8, 0})
	data = append(data, 8, 0, 0, 0)
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  142,
		UserPtr:   0x7000,
		UserLen:   24,
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFuncInfoAttrForTest(0x7000, 8, 3), 168)
	if !strings.Contains(got, "func_info=[{insn_off=0, type_id=4660}, {insn_off=8, type_id=0}, ...") {
		t.Fatalf("decodeBpfProgLoad() = %q, want bounded func_info prefix", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFuncInfoFallsBackWithoutValidPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionOut,
		ArgIndex:  142,
		UserPtr:   0x7000,
		UserLen:   8,
		CopiedLen: 8,
		ProbeRet:  0,
		Data:      makeBpfFuncInfoDataForTest([2]uint32{0, 0x1234}),
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadFuncInfoAttrForTest(0x7000, 8, 1), 168)
	if !strings.Contains(got, "func_info=0x7000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFuncInfoFallsBackWhenCountIsUnavailable(t *testing.T) {
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	data := make([]byte, 88)
	binary.LittleEndian.PutUint32(data[76:80], 8)
	binary.LittleEndian.PutUint64(data[80:88], 0x7000)

	got := decodeBpfProgLoad(ctx, data, uint32(len(data)))
	if !strings.Contains(got, "func_info=0x7000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
