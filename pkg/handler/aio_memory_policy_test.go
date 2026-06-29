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

func (r *aioPolicyMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func newAioPolicyContext(reader *aioPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		StrArgBuf:     make([]byte, BpfExitArgOffset+512),
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

func TestAioSubmitIocbDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeIocbData(1, 0x3000, 3),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_submit"
	ctx.ProbeRetEnter = 0
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}
	putSmallSnapshot(ctx, BpfEnterArgOffset, pointerBytes(0x2000))

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "1", "[0x2000]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_submit args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSetupUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: pointerBytes(0xabc),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_setup"
	ctx.Args = [6]uint64{128, 0x1000}
	ctx.Ret = 0
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, pointerBytes(0xabc))

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"128", "[0xabc]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_setup args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioSubmitDoesNotUseLegacyNestedBufferFallback(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: pointerBytes(0x2000),
		0x2000: makeIocbData(1, 0x3000, 3),
		0x3000: []byte("abc"),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_submit"
	ctx.ProbeRetEnter = 0
	ctx.Args = [6]uint64{0xabc, 1, 0x1000}
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[0:8], 0x2000)
	copy(ctx.StrArgBuf[BpfMiscArgOffset:BpfMiscArgOffset+64], makeIocbData(1, 0x3000, 3))
	ctx.DataLen = BpfMiscArgOffset + 64

	got := (&AioHandler{}).Handle(ctx).ArgParts
	if len(got) != 3 || !strings.Contains(got[2], `aio_buf=0x3000`) {
		t.Fatalf("io_submit args = %#v, want pointer aio_buf", got)
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

func TestAioPgeteventsSigmaskDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: makeSigsetData(1),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_pgetevents"
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = make([]byte, 544)
	ctx.DataLen = 544
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[528:536], 0x6000)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[536:544], 8)

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "{sigmask=0x6000, sigsetsize=8}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioPgeteventsSigmaskUsesNestedSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: makeSigsetData(1),
	}}
	decoder := event.NewDecoder()
	ctx := newAioPolicyContext(reader, decoder)
	ctx.SysName = "io_pgetevents"
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = make([]byte, 552)
	ctx.DataLen = 552
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[528:536], 0x6000)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[536:544], 8)
	copy(ctx.StrArgBuf[544:552], makeSigsetData(1))

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "{sigmask=[HUP], sigsetsize=8}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestAioPgeteventsSigmaskDoesNotUseLegacyFallback(t *testing.T) {
	reader := &aioPolicyMemoryReader{data: map[uint64][]byte{
		0x6000: makeSigsetData(1),
	}}
	ctx := newAioPolicyContext(reader, event.NewDecoder())
	ctx.SysName = "io_pgetevents"
	ctx.ProbeRetEnter = 0
	ctx.StrArgBuf = make([]byte, 544)
	ctx.DataLen = 544
	ctx.Args = [6]uint64{0xabc, 0, 0, 0, 0, 0x5000}
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[528:536], 0x6000)
	binary.LittleEndian.PutUint64(ctx.StrArgBuf[536:544], 8)

	got := (&AioHandler{}).Handle(ctx).ArgParts
	want := []string{"0xabc", "0", "0", "NULL", "NULL", "{sigmask=0x6000, sigsetsize=8}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("io_pgetevents args = %#v; want %#v", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
