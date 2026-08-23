package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfMapLookupAttr() []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], 7)
	binary.LittleEndian.PutUint64(data[8:16], 0x2000)
	binary.LittleEndian.PutUint64(data[16:24], 0x3000)
	return data
}

func TestBpfMapLookupSuccessUsesOutputPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("reader-must-not-run"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 1
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  117,
			UserPtr:   0x3000,
			UserLen:   16,
			CopiedLen: 16,
			ProbeRet:  0,
			Data:      []byte("map-value\x00\x00\x00\x00\x00\x00\x00"),
		},
	}

	got := decodeBpfMapLookup(ctx, makeBpfMapLookupAttr(), 24)
	if !strings.Contains(got, `value="map-value\0\0\0\0\0\0\0"`) {
		t.Fatalf("decodeBpfMapLookup() = %q, want output snapshot", got)
	}
	if strings.Contains(got, `"...`) {
		t.Fatalf("decodeBpfMapLookup() = %q, complete value must not be marked truncated", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapLookupFailureIgnoresOutputPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 1
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  117,
			UserPtr:   0x3000,
			UserLen:   16,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("map-value"),
		},
	}

	got := decodeBpfMapLookup(ctx, makeBpfMapLookupAttr(), 24)
	if strings.Contains(got, "map-value") || !strings.Contains(got, "value=0x3000") {
		t.Fatalf("decodeBpfMapLookup() = %q, failure output must use pointer", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func makeBpfMapBatchAttr() []byte {
	data := make([]byte, 56)
	binary.LittleEndian.PutUint64(data[8:16], 0x4000)
	binary.LittleEndian.PutUint64(data[16:24], 0x4100)
	binary.LittleEndian.PutUint64(data[24:32], 0x4200)
	binary.LittleEndian.PutUint32(data[32:36], 2)
	binary.LittleEndian.PutUint32(data[36:40], 7)
	return data
}

func TestBpfMapBatchSuccessUsesOutputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("reader-out-batch"),
		0x4100: []byte("reader-keys"),
		0x4200: []byte("reader-values"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 24
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 120, UserPtr: 0x4000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("next")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 118, UserPtr: 0x4100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("key-one!")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 119, UserPtr: 0x4200, UserLen: 16, CopiedLen: 10, ProbeRet: 0, Data: []byte("value-one")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	for _, marker := range []string{"next", "key-one!", "value-one"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("decodeBpfMapBatch() = %q, missing %q", got, marker)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapBatchFailureIgnoresOutputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 24
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 120, UserPtr: 0x4000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("next")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 118, UserPtr: 0x4100, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("key-one!")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 119, UserPtr: 0x4200, UserLen: 16, CopiedLen: 10, ProbeRet: 0, Data: []byte("value-one")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	for _, marker := range []string{"next", "key-one!", "value-one"} {
		if strings.Contains(got, marker) {
			t.Fatalf("decodeBpfMapBatch() = %q, failure must ignore %q", got, marker)
		}
	}
	if !strings.Contains(got, "out_batch=0x4000") || !strings.Contains(got, "keys=0x4100") ||
		!strings.Contains(got, "values=0x4200") {
		t.Fatalf("decodeBpfMapBatch() = %q, failure must preserve pointers", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapBatchTerminalEnoentUsesOutputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("reader-out-batch"),
		0x4100: []byte("reader-keys"),
		0x4200: []byte("reader-values"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 24
	ctx.Ret = -2
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 120, UserPtr: 0x4000, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("next")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 118, UserPtr: 0x4100, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("key1")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 119, UserPtr: 0x4200, UserLen: 16, CopiedLen: 9, ProbeRet: 0, Data: []byte("value-one")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	for _, marker := range []string{"next", "key1", "value-one"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("decodeBpfMapBatch() = %q, missing terminal output %q", got, marker)
		}
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapUpdateBatchDoesNotConsumeLookupOutputPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 26
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 118, UserPtr: 0x4100, UserLen: 1, CopiedLen: 1, ProbeRet: 0, Data: []byte("k")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 119, UserPtr: 0x4200, UserLen: 16, CopiedLen: 10, ProbeRet: 0, Data: []byte("value-one")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	if strings.Contains(got, "value-one") || strings.Contains(got, "keys=\"k\"") {
		t.Fatalf("decodeBpfMapBatch() = %q, update batch must not consume lookup output", got)
	}
	if !strings.Contains(got, "keys=0x4100") || !strings.Contains(got, "values=0x4200") {
		t.Fatalf("decodeBpfMapBatch() = %q, update batch must preserve pointers", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapUpdateBatchUsesInputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 26
	ctx.Args[1] = 0x1000
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 121, UserPtr: 0x4100, UserLen: 11, CopiedLen: 11, ProbeRet: 0, Data: []byte("update-key!")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 122, UserPtr: 0x4200, UserLen: 13, CopiedLen: 13, ProbeRet: 0, Data: []byte("update-value!")},
	}

	got := decodeBpfMapBatch(ctx, makeBpfMapBatchAttr(), 56)
	if !strings.Contains(got, `keys="update-key!"`) || !strings.Contains(got, `values="update-value!"`) {
		t.Fatalf("decodeBpfMapBatch() = %q, want enter input snapshots", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapUpdateUsesInputPayloadSections(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 2
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 126, UserPtr: 0x5100, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte{7, 0, 0, 0}},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 127, UserPtr: 0x5200, UserLen: 16, CopiedLen: 12, ProbeRet: 0, Data: []byte("update-value")},
	}

	attr := makeBpfMapLookupAttr()
	binary.LittleEndian.PutUint64(attr[8:16], 0x5100)
	binary.LittleEndian.PutUint64(attr[16:24], 0x5200)
	got := decodeBpfMapUpdate(ctx, attr, 32)
	if !strings.Contains(got, `key="\7\0\0\0"`) || !strings.Contains(got, `value="update-value"`) {
		t.Fatalf("decodeBpfMapUpdate() = %q, want enter input snapshots", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfMapUpdateDoesNotConsumeOutputPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 2
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 126, UserPtr: 0x5100, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: []byte("wrong")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 127, UserPtr: 0x5200, UserLen: 12, CopiedLen: 12, ProbeRet: 0, Data: []byte("wrong-value")},
	}

	attr := makeBpfMapLookupAttr()
	binary.LittleEndian.PutUint64(attr[8:16], 0x5100)
	binary.LittleEndian.PutUint64(attr[16:24], 0x5200)
	got := decodeBpfMapUpdate(ctx, attr, 32)
	if strings.Contains(got, "wrong") || !strings.Contains(got, "key=0x5100") || !strings.Contains(got, "value=0x5200") {
		t.Fatalf("decodeBpfMapUpdate() = %q, output payload must not be consumed", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
