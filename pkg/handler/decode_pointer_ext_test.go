package handler

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type mapMemoryReader map[uint64][]byte

func (r mapMemoryReader) Read(_ int, addr uint64, _ int) ([]byte, error) {
	data, ok := r[addr]
	if !ok {
		return nil, errors.New("unreadable address")
	}
	return append([]byte(nil), data...), nil
}

func (r mapMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func pointerBytes(ptr uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, ptr)
	return data
}

func stringArrayContext(reader mapMemoryReader) *Context {
	return &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name: "execveat",
		},
		Decoder: event.NewDecoder(),
		Opts: &cli.Options{
			StringLimit: 32,
		},
	}
}

func setExecPayloadSnapshot(ctx *Context, snapshot []byte) {
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindExecArgs,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserLen:   uint32(len(snapshot)),
			CopiedLen: uint32(len(snapshot)),
			ProbeRet:  0,
			Data:      snapshot,
		},
	}
}

func TestDecodeStringArrayReturnsPointerWithoutSnapshot(t *testing.T) {
	reader := mapMemoryReader{
		0x1000: pointerBytes(0x2000),
		0x1008: pointerBytes(0x3000),
		0x1010: pointerBytes(0),
		0x2000: append([]byte("alpha"), 0),
		0x3000: append([]byte("beta"), 0),
	}
	ctx := stringArrayContext(reader)

	if got := decodeStringArray(ctx, 0x1000, "argv"); got != "0x1000" {
		t.Fatalf("decodeStringArray(argv) = %q", got)
	}
	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000" {
		t.Fatalf("decodeStringArray(envp) = %q", got)
	}
}

func TestDecodeStringArrayReportsUnreadablePointer(t *testing.T) {
	ctx := stringArrayContext(mapMemoryReader{})

	if got := decodeStringArray(ctx, 0x1000, "argv"); got != "0x1000" {
		t.Fatalf("decodeStringArray(argv) = %q", got)
	}
	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000" {
		t.Fatalf("decodeStringArray(envp) = %q", got)
	}
}

func TestDecodeExecStringArraySnapshot(t *testing.T) {
	buf := make([]byte, 10400)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(header[4:6], 3)
	binary.LittleEndian.PutUint16(header[6:8], 5)
	negativeOne := int32(-1)
	binary.LittleEndian.PutUint32(header[8:12], uint32(negativeOne))
	binary.LittleEndian.PutUint32(header[12:16], uint32(negativeOne))
	binary.LittleEndian.PutUint64(header[16:24], 0x1238)

	writeRecord := func(index int, ptr uint64, value string) {
		offset := execSnapshotOffset + execSnapshotHeaderSize + index*execArgSnapshotSize
		record := buf[offset : offset+execArgSnapshotSize]
		binary.LittleEndian.PutUint64(record[0:8], ptr)
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(value)+1))
		copy(record[execArgDataOffset:], value)
		record[execArgDataOffset+len(value)] = 0
	}
	writeRecord(0, 0x2000, "first")
	writeRecord(1, 0x3000, "second")
	offset := execSnapshotOffset + execSnapshotHeaderSize + 2*execArgSnapshotSize
	binary.LittleEndian.PutUint64(buf[offset:offset+8], 0xffffffffffffffff)
	readFault := int32(-14)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], uint32(readFault))

	ctx := stringArrayContext(mapMemoryReader{})
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])

	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	if !ok || got != `["first", "second", 0xffffffffffffffff, ... /* 0x1238 */]` {
		t.Fatalf("decode argv snapshot = %q, %v", got, ok)
	}
	got, ok = decodeExecStringArraySnapshot(ctx, 0x4000, "envp")
	if !ok || got != "0x4000 /* 5 vars, unterminated */" {
		t.Fatalf("decode envp snapshot = %q, %v", got, ok)
	}
}

func TestDecodeExecSnapshotReportsUnreadableArrayAddress(t *testing.T) {
	buf := make([]byte, 10400)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	negativeOne := int32(-1)
	binary.LittleEndian.PutUint32(header[8:12], uint32(negativeOne))
	binary.LittleEndian.PutUint32(header[12:16], uint32(negativeOne))
	binary.LittleEndian.PutUint64(header[16:24], 0x1000)

	ctx := stringArrayContext(mapMemoryReader{})
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])

	for _, argName := range []string{"argv", "envp"} {
		got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, argName)
		if !ok || got != "0x1000" {
			t.Fatalf("decode %s snapshot = %q, %v", argName, got, ok)
		}
	}
}

func TestDecodeExecVerboseEnvSnapshot(t *testing.T) {
	buf := make([]byte, 10400)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(header[6:8], 2)
	binary.LittleEndian.PutUint32(header[12:16], 0)

	envOffset := execSnapshotOffset + execSnapshotHeaderSize + execArgSnapshotCount*execArgSnapshotSize
	for i, value := range []string{"A=1", "B=2"} {
		record := buf[envOffset+i*execArgSnapshotSize : envOffset+(i+1)*execArgSnapshotSize]
		binary.LittleEndian.PutUint64(record[0:8], uint64(0x3000+i*0x100))
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(value)+1))
		copy(record[execArgDataOffset:], value)
		record[execArgDataOffset+len(value)] = 0
	}

	ctx := stringArrayContext(mapMemoryReader{})
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])
	ctx.Opts.Verbose = true

	got, ok := decodeExecStringArraySnapshot(ctx, 0x2000, "envp")
	if !ok || got != `["A=1", "B=2"]` {
		t.Fatalf("decode verbose env snapshot = %q, %v", got, ok)
	}
}

func TestDecodeExecArgSnapshotDisplayLimit(t *testing.T) {
	buf := make([]byte, 10400)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(header[4:6], 33)
	binary.LittleEndian.PutUint32(header[8:12], 0)

	for i := 0; i < 33; i++ {
		offset := execSnapshotOffset + execSnapshotHeaderSize + i*execArgSnapshotSize
		record := buf[offset : offset+execArgSnapshotSize]
		binary.LittleEndian.PutUint64(record[0:8], uint64(0x2000+i*0x100))
		binary.LittleEndian.PutUint32(record[8:12], 2)
		record[execArgDataOffset] = 'x'
		record[execArgDataOffset+1] = 0
	}

	ctx := stringArrayContext(mapMemoryReader{})
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])

	wantShort := "[" + strings.TrimSuffix(strings.Repeat(`"x", `, 32), ", ") + ", ...]"
	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	if !ok || got != wantShort {
		t.Fatalf("decode default argv snapshot = %q, %v; want %q", got, ok, wantShort)
	}

	ctx.Opts.Verbose = true
	wantVerbose := "[" + strings.TrimSuffix(strings.Repeat(`"x", `, 33), ", ") + "]"
	got, ok = decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	if !ok || got != wantVerbose {
		t.Fatalf("decode verbose argv snapshot = %q, %v; want %q", got, ok, wantVerbose)
	}
}

func TestDecodeExecSnapshotHonorsStringLimit40(t *testing.T) {
	buf := make([]byte, 10400)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(header[4:6], 2)

	values := []string{strings.Repeat("a", 40), strings.Repeat("b", 41)}
	for i, value := range values {
		offset := execSnapshotOffset + execSnapshotHeaderSize + i*execArgSnapshotSize
		record := buf[offset : offset+execArgSnapshotSize]
		binary.LittleEndian.PutUint64(record[0:8], uint64(0x2000+i*0x100))
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(value)+1))
		copy(record[execArgDataOffset:], value)
		record[execArgDataOffset+len(value)] = 0
	}

	ctx := stringArrayContext(mapMemoryReader{})
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])
	ctx.Opts.StringLimit = 40

	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	want := `["` + values[0] + `", "` + strings.Repeat("b", 40) + `"...]`
	if !ok || got != want {
		t.Fatalf("decode -s40 argv snapshot = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeExecIgnoresLegacyStringSnapshot(t *testing.T) {
	buf := make([]byte, execSnapshotOffset+execSnapshotHeaderSize)
	header := buf[execSnapshotOffset:]
	binary.LittleEndian.PutUint32(header[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(header[4:6], 1)

	ctx := stringArrayContext(mapMemoryReader{})
	ctx.StrArgBuf = buf
	ctx.DataLen = uint32(len(buf))

	res := Result{}
	got, ok := decodeStringArrayPointer(ctx, 2, "const char *const *", "argv", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeStringArrayPointer(exec without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeWriteDumpDoesNotUseTraceeMemoryBeyondPayloadPrefix(t *testing.T) {
	data := make([]byte, 0x300)
	for i := range data {
		data[i] = byte(i)
	}
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args:      [6]uint64{1, 0x1000, uint64(len(data))},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		ProbeRetEnter: 0,
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   uint32(len(data)),
				CopiedLen: 512,
				ProbeRet:  0,
				Data:      data[:512],
			},
		},
		Opts: &cli.Options{
			StringLimit:   32,
			TraceWriteFDs: map[int32]bool{1: true},
		},
	}
	ctx.Decoder = event.NewDecoder()

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x1000, &res)
	if !ok {
		t.Fatal("decodeBufferArg did not handle write buffer")
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("write buffer summary = %q, want abbreviated string", got)
	}
	if strings.Contains(res.HexDumpStr, "00200") {
		t.Fatalf("hexdump unexpectedly included data beyond BPF prefix:\n%s", res.HexDumpStr)
	}
	if !strings.Contains(res.HexDumpStr, "Cannot fetch 256 bytes") {
		t.Fatalf("hexdump did not report missing bytes:\n%s", res.HexDumpStr)
	}
}

func TestDecodeWriteBufferIgnoresLegacyEnterSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args:      [6]uint64{1, 0x1000, 3},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		ProbeRetEnter: 0,
		StrArgBuf:     make([]byte, 1536),
		Opts:          &cli.Options{StringLimit: 32},
		Decoder:       event.NewDecoder(),
	}
	copy(ctx.StrArgBuf[:3], []byte("old"))
	ctx.DataLen = 3

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "buf", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeCharPointer(write) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeReadBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid: 101,
		Tid: 102,
		Args: [6]uint64{
			3,
			0x2000,
			32,
		},
		Ret: 5,
		ScMeta: meta.Syscall{
			Name:     "read",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionOut,
				ArgIndex:  1,
				UserPtr:   0x2000,
				UserLen:   5,
				CopiedLen: 5,
				ProbeRet:  0,
				Data:      []byte("hello"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x2000, &res)
	if !ok || got != `"hello"` {
		t.Fatalf("decodeBufferArg(read) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeWriteBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args: [6]uint64{
			1,
			0x1000,
			5,
		},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   5,
				CopiedLen: 5,
				ProbeRet:  0,
				Data:      []byte("world"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeBufferArg(ctx, 0x1000, &res)
	if !ok || got != `"world"` {
		t.Fatalf("decodeBufferArg(write) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodePathUsesPayloadStringSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "openat",
			Args:     []string{"dfd", "filename", "flags"},
			ArgTypes: []string{"int", "const char *", "int"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x3000,
				UserLen:   13,
				CopiedLen: 13,
				ProbeRet:  0,
				Data:      []byte("/tmp/section\x00"),
			},
		},
		Opts: &cli.Options{
			StringLimit: 32,
		},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "filename", 0x3000, &res)
	if !ok || got != `"/tmp/section"` {
		t.Fatalf("decodeCharPointer(path) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodePathIgnoresLegacyRawStringAndSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "openat",
			Args:     []string{"dfd", "filename", "flags"},
			ArgTypes: []string{"int", "const char *", "int"},
		},
		RawStrArg: `"/tmp/raw"`,
		StrArgBuf: make([]byte, 512),
		DataLen:   uint32(len("/tmp/legacy") + 1),
		Opts:      &cli.Options{StringLimit: 32},
		Decoder:   event.NewDecoder(),
	}
	copy(ctx.StrArgBuf, []byte("/tmp/legacy\x00"))

	res := Result{}
	got, ok := decodeCharPointer(ctx, 1, "const char *", "filename", 0x3000, &res)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeCharPointer(path without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeMemfdNameUsesPayloadStringSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "memfd_create",
			Args:     []string{"uname", "flags"},
			ArgTypes: []string{"const char *", "unsigned int"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindString,
				Direction: PayloadDirectionIn,
				ArgIndex:  0,
				UserPtr:   0x3000,
				UserLen:   13,
				CopiedLen: 13,
				ProbeRet:  0,
				Data:      []byte("section-name\x00"),
			},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "uname", 0x3000, &res)
	if !ok || got != `"section-name"` {
		t.Fatalf("decodeCharPointer(memfd_create) = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeMemfdNameIgnoresLegacySnapshot(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		ScMeta: meta.Syscall{
			Name:     "memfd_create",
			Args:     []string{"uname", "flags"},
			ArgTypes: []string{"const char *", "unsigned int"},
		},
		StrArgBuf: make([]byte, 250),
		DataLen:   12,
		Opts:      &cli.Options{StringLimit: 32},
		Decoder:   event.NewDecoder(),
	}
	copy(ctx.StrArgBuf, []byte("legacy-name\x00"))

	res := Result{}
	got, ok := decodeCharPointer(ctx, 0, "const char *", "uname", 0x3000, &res)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeCharPointer(memfd_create without section) = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeReadlinkBufferUsesPayloadSection(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Ret:       6,
		ScMeta: meta.Syscall{
			Name:     "readlink",
			Args:     []string{"path", "buf", "bufsiz"},
			ArgTypes: []string{"const char *", "char *", "size_t"},
		},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionOut,
				ArgIndex:  1,
				UserPtr:   0x3000,
				UserLen:   6,
				CopiedLen: 6,
				ProbeRet:  0,
				Data:      []byte("target"),
			},
		},
		Opts:    &cli.Options{StringLimit: 32},
		Decoder: event.NewDecoder(),
	}

	got, ok := decodeReadlinkBuffer(ctx, 1, 0x3000)
	if !ok || got != `"target"` {
		t.Fatalf("decodeReadlinkBuffer() = %q, %v; want payload section", got, ok)
	}
}

func TestDecodeReadlinkBufferIgnoresLegacyExitSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Ret:       6,
		ScMeta: meta.Syscall{
			Name:     "readlink",
			Args:     []string{"path", "buf", "bufsiz"},
			ArgTypes: []string{"const char *", "char *", "size_t"},
		},
		StrArgBuf: make([]byte, BpfExitArgOffset+6),
		Opts:      &cli.Options{StringLimit: 32},
		Decoder:   event.NewDecoder(),
	}
	copy(ctx.StrArgBuf[BpfExitArgOffset:], []byte("target"))
	ctx.DataLen = BpfExitArgOffset + 6

	got, ok := decodeReadlinkBuffer(ctx, 1, 0x3000)
	if !ok || got != "0x3000" {
		t.Fatalf("decodeReadlinkBuffer() = %q, %v; want pointer fallback", got, ok)
	}
}

func TestDecodeWriteDumpExtendsFromWrittenFile(t *testing.T) {
	data := make([]byte, 0x300)
	for i := range data {
		data[i] = byte(i)
	}
	tmp, err := os.CreateTemp(t.TempDir(), "write-data")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	if _, err := tmp.Write(make([]byte, 15)); err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Pid:       101,
		Tid:       102,
		TargetPid: 101,
		Args:      [6]uint64{1, 0x1000, uint64(len(data))},
		Ret:       int64(len(data)),
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "const char *", "size_t"},
		},
		ProbeRetEnter:      0,
		BufferFileOffset:   15,
		BufferFileOffsetOK: true,
		FdFiles:            map[string]*os.File{"101:1": tmp},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   uint32(len(data)),
				CopiedLen: 512,
				ProbeRet:  0,
				Data:      data[:512],
			},
		},
		Opts: &cli.Options{
			StringLimit:   32,
			TraceWriteFDs: map[int32]bool{1: true},
		},
	}
	ctx.Decoder = event.NewDecoder()

	res := Result{}
	if _, ok := decodeBufferArg(ctx, 0x1000, &res); !ok {
		t.Fatal("decodeBufferArg did not handle write buffer")
	}
	if !strings.Contains(res.HexDumpStr, "00200") {
		t.Fatalf("hexdump did not include data recovered from file:\n%s", res.HexDumpStr)
	}
	if strings.Contains(res.HexDumpStr, "Cannot fetch") {
		t.Fatalf("hexdump unexpectedly reported missing bytes:\n%s", res.HexDumpStr)
	}
}
