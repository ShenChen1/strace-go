package handler

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type bpfPolicyMemoryReader struct {
	data  map[uint64][]byte
	reads int
}

func (r *bpfPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
	r.reads++
	return r.readAt(addr, size)
}

func (r *bpfPolicyMemoryReader) readAt(addr uint64, size int) ([]byte, error) {
	data, ok := r.data[addr]
	if !ok {
		return nil, errors.New("unreadable address")
	}
	if size >= 0 && size < len(data) {
		data = data[:size]
	}
	return append([]byte(nil), data...), nil
}

func makeBpfMapCreateAttr(size int) []byte {
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[4:8], 4)
	binary.LittleEndian.PutUint32(data[8:12], 8)
	binary.LittleEndian.PutUint32(data[12:16], 16)
	return data
}

func makeBpfUint32Attr(values ...uint32) []byte {
	data := make([]byte, len(values)*4)
	for i, value := range values {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], value)
	}
	return data
}

func newBpfPolicyContext(reader *bpfPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Tid:           1234,
		ProbeRetEnter: -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
		Opts:          &cli.Options{},
	}
}

func TestBpfHandlerIgnoresLegacyAttrSnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.ProbeRetEnter = 0

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeBpfMapCreateAttr(16)},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "key_size=4") || !strings.Contains(got.ArgParts[1], "max_entries=16") {
		t.Fatalf("BpfHandler.Handle() arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerEfaultIgnoresPartialPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x1000, 4096}
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserLen:   4096,
			CopiedLen: 512,
			ProbeRet:  0,
			Data:      makeBpfMapCreateAttr(512),
		},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback for partial EFAULT attr", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerEfaultUsesCompletePayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserLen:   16,
			CopiedLen: 16,
			ProbeRet:  0,
			Data:      makeBpfMapCreateAttr(16),
		},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "key_size=4") || !strings.Contains(got.ArgParts[1], "max_entries=16") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want complete payload attr values", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerDoesNotReadAttrWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x1000, 16}

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerDoesNotUseLegacyAttrFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x1000, 16}

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfGetNextIdUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{11, 0x1000, 8}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeBpfUint32Attr(1, 2)},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "start_id=1") || !strings.Contains(got.ArgParts[1], "next_id=2") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want payload next-id values", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfGetNextIdUsesPartialPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{11, 0x1000, 1}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte{0xef}},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "start_id=239") || !strings.Contains(got.ArgParts[1], "next_id=0") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want partial start_id", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfGetFdByIdUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{14, 0x1000, 12}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeBpfUint32Attr(7, 0, 0)},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "map_id=7") || !strings.Contains(got.ArgParts[1], "open_flags=0") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want payload fd-by-id values", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfBtfGetFdByIdTokenUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{19, 0x1000, 16}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeBpfUint32Attr(8, 0, 0, 5)},
	}

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "btf_id=8") || !strings.Contains(got.ArgParts[1], "fd_by_id_token_fd=5") {
		t.Fatalf("BpfHandler.Handle() arg = %q, want payload BTF fd-by-id values", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerEfaultIgnoresLegacyAttrSnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.ProbeRetEnter = 0
	ctx.Ret = -14

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfHandlerEfaultDoesNotUseLegacyRawReadValidation(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.ProbeRetEnter = 0
	ctx.Ret = -14

	got := (&BpfHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("BpfHandler.Handle() arg = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfExtraDataIgnoresLegacySnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x2010: []byte{1, 2, 3},
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x2000, 600}
	ctx.Ret = -7
	cliOptionsForTest(ctx).Verbose = true

	got := checkAndFormatExtraData(ctx, 16, 600)
	if got != "" {
		t.Fatalf("checkAndFormatExtraData() = %q, want empty without payload section", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfExtraDataUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x2010: []byte{1, 2, 3},
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x2000, 600}
	ctx.Ret = -7
	cliOptionsForTest(ctx).Verbose = true
	attr := make([]byte, 32)
	attr[20] = 0x7f
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: attr},
	}

	got := checkAndFormatExtraData(ctx, 16, 600)
	if !strings.Contains(got, `\x7f`) {
		t.Fatalf("checkAndFormatExtraData() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfExtraDataDoesNotUseLegacyLargeFallback(t *testing.T) {
	extra := make([]byte, 584)
	copy(extra, []byte{1, 2, 3})
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x2010: extra,
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x2000, 600}
	ctx.Ret = -7
	cliOptionsForTest(ctx).Verbose = true

	got := checkAndFormatExtraData(ctx, 16, 600)
	if got != "" {
		t.Fatalf("checkAndFormatExtraData() = %q, want empty without snapshot bytes", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
