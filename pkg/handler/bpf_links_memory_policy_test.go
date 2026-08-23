package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfU64Array(vals ...uint64) []byte {
	data := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(data[i*8:(i+1)*8], v)
	}
	return data
}

func makeBpfU32Array(vals ...uint32) []byte {
	data := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(data[i*4:(i+1)*4], v)
	}
	return data
}

func makeBpfKprobeSymsPayload(records ...bpfKprobeSymRecordForTest) []byte {
	data := make([]byte, len(records)*bpfLinkKprobeSymRecordSize)
	for i, record := range records {
		offset := i * bpfLinkKprobeSymRecordSize
		binary.LittleEndian.PutUint64(data[offset:offset+8], record.ptr)
		binary.LittleEndian.PutUint32(data[offset+8:offset+12], uint32(record.length))
		copy(data[offset+12:offset+12+bpfLinkKprobeSymDataSize], record.data)
	}
	return data
}

type bpfKprobeSymRecordForTest struct {
	ptr    uint64
	length int32
	data   []byte
}

func TestBpfLinkSymsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfU64Array(0x2000),
		0x2000: []byte("foo\x00"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeSymsArray(ctx, 0x1000, 1)
	if got != "syms=0x1000" {
		t.Fatalf("decodeSymsArray() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkSymsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfU64Array(0x2000),
		0x2000: []byte("foo\x00"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeSymsArray(ctx, 0x1000, 1)
	if got != "syms=0x1000" {
		t.Fatalf("decodeSymsArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkSymsUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkKprobeSymsPayloadArg,
			UserPtr:   0x1000,
			UserLen:   4 * bpfLinkKprobeSymRecordSize,
			CopiedLen: 4 * bpfLinkKprobeSymRecordSize,
			ProbeRet:  0,
			Data: makeBpfKprobeSymsPayload(
				bpfKprobeSymRecordForTest{ptr: 0x2000, length: 4, data: []byte("foo\x00")},
				bpfKprobeSymRecordForTest{},
				bpfKprobeSymRecordForTest{ptr: 0x3000, length: 3, data: []byte("OH\x00")},
				bpfKprobeSymRecordForTest{
					ptr:    0x4000,
					length: bpfLinkKprobeSymDataSize,
					data:   []byte("abcdefghijklmnopqrstuvwxyz0123456789"),
				},
			),
		},
	}

	got := decodeSymsArray(ctx, 0x1000, 4)
	want := `syms=["foo", NULL, "OH", "abcdefghijklmnopqrstuvwxyz012345"...]`
	if got != want {
		t.Fatalf("decodeSymsArray() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkSymsUsesNestedPayloadSectionWithEllipsis(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkKprobeSymsPayloadArg,
			UserPtr:   0x1000,
			UserLen:   5 * bpfLinkKprobeSymRecordSize,
			CopiedLen: 4 * bpfLinkKprobeSymRecordSize,
			ProbeRet:  0,
			Data: makeBpfKprobeSymsPayload(
				bpfKprobeSymRecordForTest{ptr: 0x2000, length: 4, data: []byte("foo\x00")},
				bpfKprobeSymRecordForTest{},
				bpfKprobeSymRecordForTest{ptr: 0x3000, length: 3, data: []byte("OH\x00")},
				bpfKprobeSymRecordForTest{
					ptr:    0x4000,
					length: bpfLinkKprobeSymDataSize,
					data:   []byte("abcdefghijklmnopqrstuvwxyz0123456789"),
				},
			),
		},
	}

	got := decodeSymsArray(ctx, 0x1000, 5)
	want := `syms=["foo", NULL, "OH", "abcdefghijklmnopqrstuvwxyz012345"..., ... /* 0x1020 */]`
	if got != want {
		t.Fatalf("decodeSymsArray() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkU64ArrayDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBpfU64Array(0, 1, 0xbadc0ded),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeU64Array(ctx, "addrs", 0x3000, 3)
	if got != "addrs=0x3000" {
		t.Fatalf("decodeU64Array() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkU64ArrayDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBpfU64Array(0, 1, 0xbadc0ded),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeU64Array(ctx, "addrs", 0x3000, 3)
	if got != "addrs=0x3000" {
		t.Fatalf("decodeU64Array() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkU64ArrayUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkKprobeAddrsPayloadArg,
			UserPtr:   0x3000,
			UserLen:   32,
			CopiedLen: 32,
			ProbeRet:  0,
			Data:      makeBpfU64Array(0, 1, 0xbadc0ded, 0xfacefeeddeadc0de),
		},
	}

	got := decodeU64Array(ctx, "addrs", 0x3000, 4)
	want := "addrs=[0, 0x1, 0xbadc0ded, 0xfacefeeddeadc0de]"
	if got != want {
		t.Fatalf("decodeU64Array() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkU64ArrayUsesNestedPayloadSectionWithEllipsis(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkKprobeCookiesPayloadArg,
			UserPtr:   0x5000,
			UserLen:   40,
			CopiedLen: 32,
			ProbeRet:  0,
			Data:      makeBpfU64Array(0, 1, 0xbadc0ded, 0xfacefeeddeadc0de),
		},
	}

	got := decodeU64Array(ctx, "cookies", 0x5000, 5)
	want := "cookies=[0, 0x1, 0xbadc0ded, 0xfacefeeddeadc0de, ... /* 0x5020 */]"
	if got != want {
		t.Fatalf("decodeU64Array() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkIterInfoDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: makeBpfU32Array(42),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeBpfIterInfo(ctx, 0x4000, 1)
	if got != "iter_info=0x4000" {
		t.Fatalf("decodeBpfIterInfo() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkIterInfoDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: makeBpfU32Array(42),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeBpfIterInfo(ctx, 0x4000, 1)
	if got != "iter_info=0x4000" {
		t.Fatalf("decodeBpfIterInfo() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkIterInfoUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  107,
			UserPtr:   0x4000,
			UserLen:   20,
			CopiedLen: 20,
			ProbeRet:  0,
			Data:      makeBpfU32Array(0, 42, 314159265, 3134983661, 0xffffffff),
		},
	}

	got := decodeBpfIterInfo(ctx, 0x4000, 5)
	want := "iter_info=[{map={map_fd=0}}, {map={map_fd=42}}, {map={map_fd=314159265}}, {map={map_fd=-1159983635}}, {map={map_fd=-1}}]"
	if got != want {
		t.Fatalf("decodeBpfIterInfo() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkIterInfoUsesNestedPayloadSectionWithEllipsis(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  107,
			UserPtr:   0x4000,
			UserLen:   24,
			CopiedLen: 20,
			ProbeRet:  0,
			Data:      makeBpfU32Array(0, 42, 314159265, 3134983661, 0xffffffff),
		},
	}

	got := decodeBpfIterInfo(ctx, 0x4000, 6)
	want := "iter_info=[{map={map_fd=0}}, {map={map_fd=42}}, {map={map_fd=314159265}}, {map={map_fd=-1159983635}}, {map={map_fd=-1}}, ... /* 0x4014 */]"
	if got != want {
		t.Fatalf("decodeBpfIterInfo() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfPolicyContext(reader, decoder)

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != "0x5000" {
		t.Fatalf("decodeStreamBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x5000: []byte("bPf\x00daTum"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != "0x5000" {
		t.Fatalf("decodeStreamBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkStreamBufPayloadArg,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("bPf\x00daTum"),
		},
	}

	got := decodeStreamBuf(ctx, 0x5000, 9)
	want := `"bPf\0daTum"`
	if got != want {
		t.Fatalf("decodeStreamBuf() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufUsesExitOutputPayloadSection(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 37
	ctx.Ret = 9
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  bpfLinkStreamBufPayloadArg,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("bPf\x00daTum"),
		},
	}

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != `"bPf\0daTum"` {
		t.Fatalf("decodeStreamBuf() = %q, want exit output snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufUsesOutputSectionWhenExitReturnsZero(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 37
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  bpfLinkStreamBufPayloadArg,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("bPf\x00daTum"),
		},
	}

	if got := decodeStreamBuf(ctx, 0x5000, 9); got != `"bPf\0daTum"` {
		t.Fatalf("decodeStreamBuf() = %q, want zero-byte exit output snapshot", got)
	}
}

func TestBpfLinkStreamBufDoesNotConsumeEnterInputAsExitOutput(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 37
	ctx.Ret = 9
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfLinkStreamBufPayloadArg,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("stale-data"),
		},
	}

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != "0x5000" {
		t.Fatalf("decodeStreamBuf() = %q, enter payload must not be treated as output", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfLinkStreamBufUsesReadableOutputOnFailedExit(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 37
	ctx.Ret = -22
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionOut,
			ArgIndex:  bpfLinkStreamBufPayloadArg,
			UserPtr:   0x5000,
			UserLen:   9,
			CopiedLen: 9,
			ProbeRet:  0,
			Data:      []byte("bPf\x00daTum"),
		},
	}

	got := decodeStreamBuf(ctx, 0x5000, 9)
	if got != `"bPf\0daTum"` {
		t.Fatalf("decodeStreamBuf() = %q, want readable failed-exit snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
