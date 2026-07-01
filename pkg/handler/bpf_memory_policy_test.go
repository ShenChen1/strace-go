package handler

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

type bpfPolicyMemoryReader struct {
	data        map[uint64][]byte
	reads       int
	robustReads int
}

func (r *bpfPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
	r.reads++
	return r.readAt(addr, size)
}

func (r *bpfPolicyMemoryReader) ReadRobust(_ int, addr uint64, size int, _ bool) ([]byte, error) {
	r.robustReads++
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

func newBpfPolicyContext(reader *bpfPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Tid:           1234,
		ProbeRetEnter: -1,
		Decoder:       decoder,
		Opts:          &cli.Options{},
	}
}

func TestBpfHandlerUsesSnapshotWithoutMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = makeBpfMapCreateAttr(16)
	ctx.DataLen = uint32(len(ctx.StrArgBuf))

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "key_size=4") || !strings.Contains(got.ArgParts[1], "max_entries=16") {
		t.Fatalf("BpfHandler.Handle() arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfHandlerEfaultDoesNotRawReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfMapCreateAttr(16),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x1000, 16}
	ctx.ProbeRetEnter = 0
	ctx.Ret = -14
	ctx.StrArgBuf = makeBpfMapCreateAttr(16)
	ctx.DataLen = uint32(len(ctx.StrArgBuf))

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "key_size=4") {
		t.Fatalf("BpfHandler.Handle() arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	ctx.StrArgBuf = makeBpfMapCreateAttr(16)
	ctx.DataLen = uint32(len(ctx.StrArgBuf))

	got := (&BpfHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[1], "key_size=4") {
		t.Fatalf("BpfHandler.Handle() arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfExtraDataDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x2010: []byte{1, 2, 3},
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)
	ctx.Args = [6]uint64{0, 0x2000, 600}
	ctx.Ret = -7
	ctx.Opts.Verbose = true
	ctx.StrArgBuf = make([]byte, 512)
	ctx.StrArgBuf[20] = 0x7f

	got := checkAndFormatExtraData(ctx, 16, 600)
	if !strings.Contains(got, `\x7f`) {
		t.Fatalf("checkAndFormatExtraData() = %q", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}

func TestBpfExtraDataUsesPayloadBytesSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x2010: []byte{1, 2, 3},
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args = [6]uint64{0, 0x2000, 600}
	ctx.Ret = -7
	ctx.Opts.Verbose = true
	attr := make([]byte, 32)
	attr[20] = 0x7f
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: attr},
	}

	got := checkAndFormatExtraData(ctx, 16, 600)
	if !strings.Contains(got, `\x7f`) {
		t.Fatalf("checkAndFormatExtraData() = %q", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
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
	ctx.Opts.Verbose = true
	ctx.StrArgBuf = make([]byte, 512)

	got := checkAndFormatExtraData(ctx, 16, 600)
	if got != "" {
		t.Fatalf("checkAndFormatExtraData() = %q, want empty without snapshot bytes", got)
	}
	if reader.reads != 0 || reader.robustReads != 0 {
		t.Fatalf("memory reads = raw:%d robust:%d, want 0", reader.reads, reader.robustReads)
	}
}
