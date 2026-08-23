package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgLoadLineInfoAttrForTest(ptr uint64, recSize, count uint32) []byte {
	data := make([]byte, 168)
	binary.LittleEndian.PutUint32(data[92:96], recSize)
	binary.LittleEndian.PutUint64(data[96:104], ptr)
	binary.LittleEndian.PutUint32(data[104:108], count)
	return data
}

func makeBpfProgLoadCoreRelosAttrForTest(ptr uint64, recSize, count uint32) []byte {
	data := make([]byte, 168)
	binary.LittleEndian.PutUint32(data[116:120], count)
	binary.LittleEndian.PutUint64(data[128:136], ptr)
	binary.LittleEndian.PutUint32(data[136:140], recSize)
	return data
}

func makeBpfProgLoadRecordsForTest(records ...[4]uint32) []byte {
	data := make([]byte, len(records)*16)
	for i, record := range records {
		for field, value := range record {
			offset := i*16 + field*4
			binary.LittleEndian.PutUint32(data[offset:offset+4], value)
		}
	}
	return data
}

func TestBpfProgLoadLineInfoUsesNestedPayloadSection(t *testing.T) {
	data := makeBpfProgLoadRecordsForTest(
		[4]uint32{0, 4, 8, 0x10001},
		[4]uint32{16, 20, 24, 0x20002},
	)
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  143,
		UserPtr:   0x8000,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadLineInfoAttrForTest(0x8000, 16, 2), 168)
	want := "line_info=[{insn_off=0, file_name_off=4, line_off=8, line_col=65537}, {insn_off=16, file_name_off=20, line_off=24, line_col=131074}]"
	if !strings.Contains(got, want) {
		t.Fatalf("decodeBpfProgLoad() = %q, want line_info records", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadCoreRelosUsesNestedPayloadSection(t *testing.T) {
	data := makeBpfProgLoadRecordsForTest(
		[4]uint32{0, 0x1234, 4, 1},
		[4]uint32{16, 0x5678, 8, 2},
	)
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  144,
		UserPtr:   0x9000,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadCoreRelosAttrForTest(0x9000, 16, 2), 168)
	want := "core_relos=[{insn_off=0, type_id=4660, access_str_off=4, kind=1}, {insn_off=16, type_id=22136, access_str_off=8, kind=2}]"
	if !strings.Contains(got, want) {
		t.Fatalf("decodeBpfProgLoad() = %q, want core_relos records", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadDebugRecordsFallbackWithoutValidPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionOut,
		ArgIndex:  143,
		UserPtr:   0x8000,
		UserLen:   16,
		CopiedLen: 16,
		ProbeRet:  0,
		Data:      makeBpfProgLoadRecordsForTest([4]uint32{0, 4, 8, 1}),
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadLineInfoAttrForTest(0x8000, 16, 1), 168)
	if !strings.Contains(got, "line_info=0x8000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want line_info pointer fallback", got)
	}
	got = decodeBpfProgLoad(ctx, makeBpfProgLoadCoreRelosAttrForTest(0x9000, 16, 1), 136)
	if !strings.Contains(got, "core_relos=0x9000") {
		t.Fatalf("decodeBpfProgLoad() = %q, want core_relos pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadDebugRecordsPreserveBoundedPrefix(t *testing.T) {
	data := makeBpfProgLoadRecordsForTest([4]uint32{0, 4, 8, 1})
	reader := &bpfPolicyMemoryReader{}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  143,
		UserPtr:   0x8000,
		UserLen:   32,
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadLineInfoAttrForTest(0x8000, 16, 2), 168)
	if !strings.Contains(got, "line_info=[{insn_off=0, file_name_off=4, line_off=8, line_col=1}, ...") {
		t.Fatalf("decodeBpfProgLoad() = %q, want bounded line_info prefix", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
