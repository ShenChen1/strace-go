package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgQueryAttrForTest() []byte {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:4], 7)
	binary.LittleEndian.PutUint32(data[4:8], 0)
	binary.LittleEndian.PutUint64(data[16:24], 0x8100)
	binary.LittleEndian.PutUint32(data[24:28], 4)
	binary.LittleEndian.PutUint64(data[32:40], 0x8200)
	binary.LittleEndian.PutUint64(data[40:48], 0x8300)
	binary.LittleEndian.PutUint64(data[48:56], 0x8400)
	binary.LittleEndian.PutUint64(data[56:64], 0x55)
	return data
}

func bpfProgQueryU32Bytes(values ...uint32) []byte {
	data := make([]byte, len(values)*4)
	for i, value := range values {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], value)
	}
	return data
}

func TestBpfProgQueryUsesExitSnapshotsForAllOutputArrays(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{16, 0x8000, 64}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 132, UserPtr: 0x8018, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: bpfProgQueryU32Bytes(2)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 128, UserPtr: 0x8100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: bpfProgQueryU32Bytes(11, 22)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 129, UserPtr: 0x8200, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: bpfProgQueryU32Bytes(1, 3)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 130, UserPtr: 0x8300, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: bpfProgQueryU32Bytes(33, 44)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 131, UserPtr: 0x8400, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: bpfProgQueryU32Bytes(2, 4)},
	}

	got := decodeBpfProgQuery(ctx, makeBpfProgQueryAttrForTest(), 64)
	for _, want := range []string{
		"prog_ids=[11, 22]",
		"prog_cnt=2",
		"prog_attach_flags=[BPF_F_ALLOW_OVERRIDE, BPF_F_ALLOW_OVERRIDE|BPF_F_ALLOW_MULTI]",
		"link_ids=[33, 44]",
		"link_attach_flags=[BPF_F_ALLOW_MULTI, BPF_F_REPLACE]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfProgQuery() = %q, missing %q", got, want)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgQueryOutputSnapshotsRequireExitDirection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{16, 0x8000, 64}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 128, UserPtr: 0x8100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: bpfProgQueryU32Bytes(11, 22)},
	}

	got := decodeBpfProgQuery(ctx, makeBpfProgQueryAttrForTest(), 64)
	if !strings.Contains(got, "prog_ids=0x8100") || strings.Contains(got, "prog_ids=[11, 22]") {
		t.Fatalf("decodeBpfProgQuery() = %q, IN snapshot must not be used as OUT", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgQueryZeroCountKeepsEmptyArrayWithoutSnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{16, 0x8000, 64}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 132, UserPtr: 0x8018, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: bpfProgQueryU32Bytes(0)},
	}

	got := decodeBpfProgQuery(ctx, makeBpfProgQueryAttrForTest(), 64)
	if !strings.Contains(got, "prog_ids=[]") || !strings.Contains(got, "prog_cnt=0") {
		t.Fatalf("decodeBpfProgQuery() = %q, want empty output array", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
