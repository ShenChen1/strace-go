package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfTaskFdQueryAttrForTest() []byte {
	data := make([]byte, 48)
	binary.LittleEndian.PutUint32(data[0:4], 1234)
	binary.LittleEndian.PutUint32(data[4:8], 7)
	binary.LittleEndian.PutUint32(data[8:12], 0)
	binary.LittleEndian.PutUint32(data[12:16], 64)
	binary.LittleEndian.PutUint64(data[16:24], 0x7000)
	return data
}

func makeBpfTaskFdQueryOutputAttrForTest() []byte {
	data := makeBpfTaskFdQueryAttrForTest()
	binary.LittleEndian.PutUint32(data[12:16], 16)
	binary.LittleEndian.PutUint32(data[24:28], 99)
	binary.LittleEndian.PutUint32(data[28:32], 1)
	binary.LittleEndian.PutUint64(data[32:40], 0x120)
	binary.LittleEndian.PutUint64(data[40:48], 0x340)
	return data
}

func TestBpfTaskFdQueryUsesExitBufferStringPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x7000: []byte("reader-must-not-run\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{20, 0x6000, 48}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  138,
			UserPtr:   0x6000,
			UserLen:   48,
			CopiedLen: 48,
			ProbeRet:  0,
			Data:      makeBpfTaskFdQueryOutputAttrForTest(),
		},
		{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionOut,
			ArgIndex:  137,
			UserPtr:   0x7000,
			UserLen:   24,
			CopiedLen: 24,
			ProbeRet:  0,
			Data:      []byte("sys_enter_getpid\x00"),
		},
	}

	got := decodeBpfTaskFdQuery(ctx, makeBpfTaskFdQueryAttrForTest(), 48)
	for _, want := range []string{
		`buf="sys_enter_getpid"`,
		"buf_len=16",
		"prog_id=99",
		"fd_type=BPF_FD_TYPE_TRACEPOINT",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfTaskFdQuery() = %q, missing %q", got, want)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfTaskFdQueryFallsBackToPointerWithoutExitPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x7000: []byte("reader-must-not-run\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfTaskFdQuery(ctx, makeBpfTaskFdQueryAttrForTest(), 48)
	if !strings.Contains(got, "buf=0x7000") {
		t.Fatalf("decodeBpfTaskFdQuery() = %q, missing pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
