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

func makeBpfBtfLoadLogAttr() []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[8:16], 0x6000)
	binary.LittleEndian.PutUint32(data[20:24], 32)
	binary.LittleEndian.PutUint32(data[24:28], 1)
	return data
}

func TestBpfBtfLoadFailurePrefersVerifierLogOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: []byte("reader-must-not-run"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Ret = -22
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 114, UserPtr: 0x6000, UserLen: 13, CopiedLen: 13, ProbeRet: 0, Data: []byte("btf-verifier-log")},
	}

	got := decodeBpfBtfLoad(ctx, makeBpfBtfLoadLogAttr(), 32)
	if !strings.Contains(got, `btf_log_buf="btf-verifier-log"`) {
		t.Fatalf("decodeBpfBtfLoad() = %q, want verifier OUT snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfBtfLoadSuccessIgnoresVerifierLogOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 114, UserPtr: 0x6000, UserLen: 13, CopiedLen: 13, ProbeRet: 0, Data: []byte("btf-verifier-log")},
	}

	got := decodeBpfBtfLoad(ctx, makeBpfBtfLoadLogAttr(), 32)
	if !strings.Contains(got, "btf_log_buf=0x6000") || strings.Contains(got, "btf-verifier-log") {
		t.Fatalf("decodeBpfBtfLoad() = %q, success OUT payload must be ignored", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func makeBpfProgTestRunAttr() []byte {
	data := make([]byte, 80)
	binary.LittleEndian.PutUint32(data[8:12], 4)
	binary.LittleEndian.PutUint32(data[12:16], 8)
	binary.LittleEndian.PutUint64(data[16:24], 0x7000)
	binary.LittleEndian.PutUint64(data[24:32], 0x7100)
	binary.LittleEndian.PutUint32(data[40:44], 4)
	binary.LittleEndian.PutUint32(data[44:48], 8)
	binary.LittleEndian.PutUint64(data[48:56], 0x7200)
	binary.LittleEndian.PutUint64(data[56:64], 0x7300)
	return data
}

func TestBpfProgTestRunSuccessUsesOutputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x7100: []byte("reader-data-out"),
		0x7300: []byte("reader-ctx-out"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 115, UserPtr: 0x7100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("data-out")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 116, UserPtr: 0x7300, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("ctx-out!")},
	}

	got := decodeBpfProgTestRun(ctx, makeBpfProgTestRunAttr(), 80)
	if !strings.Contains(got, `data_out="data-out"`) || !strings.Contains(got, `ctx_out="ctx-out!"`) {
		t.Fatalf("decodeBpfProgTestRun() = %q, want both output snapshots", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgTestRunFailureIgnoresOutputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Ret = -22
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 115, UserPtr: 0x7100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("data-out")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 116, UserPtr: 0x7300, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("ctx-out!")},
	}

	got := decodeBpfProgTestRun(ctx, makeBpfProgTestRunAttr(), 80)
	if strings.Contains(got, "data-out") || strings.Contains(got, "ctx-out!") ||
		!strings.Contains(got, "data_out=0x7100") || !strings.Contains(got, "ctx_out=0x7300") {
		t.Fatalf("decodeBpfProgTestRun() = %q, failure output sections must be ignored", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
