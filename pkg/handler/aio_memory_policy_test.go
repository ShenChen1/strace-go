package handler

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

type aioPolicyMemoryReader struct {
	data  map[uint64][]byte
	reads int
}

func (r *aioPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
	r.reads++
	data, ok := r.data[addr]
	if !ok {
		return nil, errors.New("unreadable address")
	}
	if size >= 0 && size < len(data) {
		data = data[:size]
	}
	return append([]byte(nil), data...), nil
}

func newAioPolicyContext(reader *aioPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		Opts:          &cli.Options{StringLimit: 32},
	}
}

func makeIocbData(opcode uint16, buf uint64, nbytes uint64) []byte {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint16(data[16:18], opcode)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[24:32], buf)
	binary.LittleEndian.PutUint64(data[32:40], nbytes)
	return data
}

func TestAioSubmitPointerArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: pointerBytes(0x2000),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_submit"
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "1", "0x1000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_submit args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSubmitPointerArrayIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeIocbData(1, 0x3000, 3),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_submit"
	ctx.ProbeRetEnter = 0
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "1", "0x1000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_submit args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSetupIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: pointerBytes(0xabc),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_setup"
	ctx.Args = [6]uint64{128, 0x1000}
	ctx.Ret = 0
	ctx.ProbeRetExit = 0

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"128", "0x1000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_setup args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSetupUsesPayloadStructSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_setup"
	ctx.Args = [6]uint64{128, 0x1000}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: pointerBytes(0xabc)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"128", "[0xabc]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_setup args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSubmitFallsBackToPointerWithoutIocbPayloadSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: pointerBytes(0x2000),
		0x2000: makeIocbData(1, 0x3000, 3),
		0x3000: []byte("abc"),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_submit"
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: pointerBytes(0x2000)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "1", "[0x2000]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_submit args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSubmitUsesPayloadSections(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_submit"
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: pointerBytes(0x2000)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: AioSubmitIocbPayloadArgBase, ProbeRet: 0, Data: makeIocbData(1, 0x3000, 3)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	if len(got) != 3 || !strings.Contains(got[2], `aio_buf=0x3000`) {
		t.Fatalf("io_submit args = %#v, want payload aio_buf", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSubmitUsesTruncatedPointerArrayPayloadSections(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_submit"
	ctx.Args = [6]uint64{0xabc, 65, 0x1000}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			ProbeRet:  0,
			UserLen:   520,
			CopiedLen: 16,
			Data:      append(pointerBytes(0x2000), pointerBytes(0x3000)...),
		},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: AioSubmitIocbPayloadArgBase, ProbeRet: 0, Data: makeIocbData(1, 0x4000, 3)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: AioSubmitIocbPayloadArgBase + 1, ProbeRet: 0, Data: makeIocbData(1, 0x5000, 4)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	if len(got) != 3 ||
		!strings.Contains(got[2], `aio_buf=0x4000`) ||
		!strings.Contains(got[2], `aio_buf=0x5000`) ||
		!strings.Contains(got[2], `... /* 0x1010 */`) {
		t.Fatalf("io_submit args = %#v, want bounded payload prefix with truncation marker", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioBufferDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: []byte("abc"),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)

	got := (&AioHandler{}).formatAioBuf(ctx, 1, 0x3000, 3)
	if got != "0x3000" {
		t.Fatalf("formatAioBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioIovecDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: iovecBytes([2]uint64{0x4000, 3}),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)

	got := (&AioHandler{}).formatAioBuf(ctx, 7, 0x3000, 1)
	if got != "0x3000" {
		t.Fatalf("formatAioBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioCancelUsesPayloadStructSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_cancel"
	ctx.Args = [6]uint64{0xabc, 0x2000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeIocbData(1, 0x3000, 3)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	if len(got) != 3 || !strings.Contains(got[1], `aio_buf=0x3000`) {
		t.Fatalf("io_cancel args = %#v, want payload aio_buf", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioCancelDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeIocbData(1, 0x3000, 3),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_cancel"
	ctx.Args = [6]uint64{0xabc, 0x2000, 0}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0x2000", "NULL"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_cancel args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioGeteventsUsesPayloadStructSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_getevents"
	ctx.Args = [6]uint64{0xabc, 0, 1, 0x7000, 0}
	ctx.Ret = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 3, ProbeRet: 0, Data: makeAioIoEventData(0x11, 0x22, 3, 4)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "1", "[{data=0x11, obj=0x22, res=3, res2=4}]", "NULL"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_getevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioGeteventsTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_getevents"
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0x4000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: makeTimeStruct(5, 6)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "{tv_sec=5, tv_nsec=6}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_getevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioPgeteventsSigsetIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: makeSigsetData(1),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_pgetevents"
	ctx.ProbeRetEnter = 0
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "0x5000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioPgeteventsSigsetUsesPayloadSections(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_pgetevents"
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: append(pointerBytes(0x6000), pointerBytes(8)...)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: makeSigsetData(1)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "{sigmask=[HUP], sigsetsize=8}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioPgeteventsSigmaskFallsBackToPointerWithoutPayloadSection(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: makeSigsetData(1),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_pgetevents"
	ctx.ProbeRetEnter = 0
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: append(pointerBytes(0x6000), pointerBytes(8)...)},
	}

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "{sigmask=0x6000, sigsetsize=8}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func makeAioIoEventData(dataValue uint64, obj uint64, res uint64, res2 uint64) []byte {
	data := make([]byte, aioEventsElemSize)
	binary.LittleEndian.PutUint64(data[0:8], dataValue)
	binary.LittleEndian.PutUint64(data[8:16], obj)
	binary.LittleEndian.PutUint64(data[16:24], res)
	binary.LittleEndian.PutUint64(data[24:32], res2)
	return data
}
