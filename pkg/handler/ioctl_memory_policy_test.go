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

type ioctlPolicyMemoryReader struct {
	data  map[uint64][]byte
	reads int
}

func (r *ioctlPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
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

func newIoctlPolicyContext(reader *ioctlPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Ret:           -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
		Opts:          &cli.Options{StringLimit: 32},
		Runtime:       NewRuntime(),
	}
}

func makeDmIoctlData() []byte {
	data := make([]byte, 312)
	binary.LittleEndian.PutUint32(data[0:4], 4)
	binary.LittleEndian.PutUint32(data[12:16], 312)
	copy(data[32:160], []byte("dm-test"))
	copy(data[160:288], []byte("uuid-test"))
	return data
}

func makeIoctlUint32Data(v uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, v)
	return data
}

func makeFiemapData(start, length uint64, flags, mapped, count uint32) []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[0:8], start)
	binary.LittleEndian.PutUint64(data[8:16], length)
	binary.LittleEndian.PutUint32(data[16:20], flags)
	binary.LittleEndian.PutUint32(data[20:24], mapped)
	binary.LittleEndian.PutUint32(data[24:28], count)
	return data
}

func makeFiemapExtent(logical, physical, length uint64, flags uint32) []byte {
	data := make([]byte, 48)
	binary.LittleEndian.PutUint64(data[0:8], logical)
	binary.LittleEndian.PutUint64(data[8:16], physical)
	binary.LittleEndian.PutUint64(data[16:24], length)
	binary.LittleEndian.PutUint32(data[32:36], flags)
	return data
}

func TestIoctlDmIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeDmIoctlData(),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0

	got := (&IoctlHandler{}).decodeDmIoctl(ctx, 0x1000, "DM_VERSION")
	if got != "0x1000" {
		t.Fatalf("decodeDmIoctl() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlDmUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: makeDmIoctlData()},
	}

	got := (&IoctlHandler{}).decodeDmIoctl(ctx, 0x1000, "DM_VERSION")
	if !strings.Contains(got, "version=[4, 0, 0]") || !strings.Contains(got, `name="dm-test"`) {
		t.Fatalf("decodeDmIoctl() = %q", got)
	}
}

func TestIoctlDmDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeDmIoctlData(),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeDmIoctl(ctx, 0x1000, "DM_VERSION")
	if got != "0x1000" {
		t.Fatalf("decodeDmIoctl() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlDmDoesNotUseTraceeMemoryFallback(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeDmIoctlData(),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())

	got := (&IoctlHandler{}).decodeDmIoctl(ctx, 0x1000, "DM_VERSION")
	if got != "0x1000" {
		t.Fatalf("decodeDmIoctl() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlOtpDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeIoctlUint32Data(1),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x80044d0d, 0x2000)
	if got != "0x2000" {
		t.Fatalf("decodeStandardIoctlArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlOtpIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeIoctlUint32Data(1),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())
	ctx.ProbeRetEnter = 0

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x80044d0d, 0x2000)
	if got != "0x2000" {
		t.Fatalf("decodeStandardIoctlArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlOtpUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x2000, ProbeRet: 0, Data: makeIoctlUint32Data(1)},
	}

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x80044d0d, 0x2000)
	if got != "[MTD_OTP_FACTORY]" {
		t.Fatalf("decodeStandardIoctlArg() = %q", got)
	}
}

func TestIoctlFionreadUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, UserPtr: 0x4000, ProbeRet: 0, Data: makeIoctlUint32Data(17)},
	}

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x541b, 0x4000)
	if got != "[17]" {
		t.Fatalf("decodeStandardIoctlArg(FIONREAD) = %q", got)
	}
}

func TestIoctlFionreadFallsBackToPointerWithoutSnapshot(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x541b, 0x4000)
	if got != "0x4000" {
		t.Fatalf("decodeStandardIoctlArg(FIONREAD) = %q, want pointer fallback", got)
	}
}

func TestIoctlTcgetsUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, UserPtr: 0x5000, ProbeRet: 0, Data: make([]byte, 36)},
	}

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x5401, 0x5000)
	if got != "{...}" {
		t.Fatalf("decodeStandardIoctlArg(TCGETS) = %q", got)
	}
}

func TestIoctlTcsetsUsesInputPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x5000, ProbeRet: 0, Data: make([]byte, 36)},
	}

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x5402, 0x5000)
	if got != "{...}" {
		t.Fatalf("decodeStandardIoctlArg(TCSETS) = %q", got)
	}
}

func TestIoctlWinsizeUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, UserPtr: 0x6000, ProbeRet: 0, Data: make([]byte, 8)},
	}

	got := (&IoctlHandler{}).decodeStandardIoctlArg(ctx, 0x5413, 0x6000)
	if got != "{...}" {
		t.Fatalf("decodeStandardIoctlArg(TIOCGWINSZ) = %q", got)
	}
}

func TestIoctlFiemapHeaderDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeFiemapData(1, 2, 1, 0, 0),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)
	_ = (&IoctlHandler{}).decodeFiemap(ctx, 0x3000)
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlFiemapHeaderIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeFiemapData(1, 2, 1, 0, 0),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())
	ctx.ProbeRetEnter = 0
	got := (&IoctlHandler{}).decodeFiemap(ctx, 0x3000)
	if strings.Contains(got, "fm_start=1,") || strings.Contains(got, "fm_length=2,") {
		t.Fatalf("decodeFiemap() = %q, want synthetic fallback without payload section", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlFiemapHeaderUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: makeFiemapData(1, 2, 1, 0, 0)},
	}
	got := (&IoctlHandler{}).decodeFiemap(ctx, 0x3000)
	if !strings.Contains(got, "fm_start=1") || !strings.Contains(got, "fm_length=2") {
		t.Fatalf("decodeFiemap() = %q", got)
	}
}

func TestIoctlFiemapExtentsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3030: makeFiemapExtent(1, 2, 3, 1),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	_ = (&IoctlHandler{}).formatFiemapExtents(ctx, 0x3010, 1, 1, 1)
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlFiemapExtentsIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3030: makeFiemapExtent(1, 2, 3, 1),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())
	ctx.ProbeRetEnter = 0

	got := (&IoctlHandler{}).formatFiemapExtents(ctx, 0x3010, 1, 1, 1)
	if got != "[]" {
		t.Fatalf("formatFiemapExtents() = %q, want empty without payload section", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestIoctlFiemapExtentsUsesPayloadBytesSection(t *testing.T) {
	payload := append(makeFiemapData(1, 2, 1, 1, 1), makeFiemapExtent(1, 2, 3, 1)...)
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: payload},
	}

	got := (&IoctlHandler{}).formatFiemapExtents(ctx, 0x3010, 1, 1, 1)
	if !strings.Contains(got, "fe_logical=1") || !strings.Contains(got, "fe_physical=2") {
		t.Fatalf("formatFiemapExtents() = %q", got)
	}
}

func TestIoctlFiemapExtentsDoesNotUseTraceeMemoryFallback(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3030: makeFiemapExtent(1, 2, 3, 1),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())

	got := (&IoctlHandler{}).formatFiemapExtents(ctx, 0x3010, 1, 1, 1)
	if got != "[]" {
		t.Fatalf("formatFiemapExtents() = %q, want empty without snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
