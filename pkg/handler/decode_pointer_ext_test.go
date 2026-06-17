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
		MemReader: reader,
		Decoder:   event.NewDecoder(reader),
		Opts: &cli.Options{
			StringLimit: 32,
		},
	}
}

func TestDecodeStringArrayUsesTraceeMemory(t *testing.T) {
	reader := mapMemoryReader{
		0x1000: pointerBytes(0x2000),
		0x1008: pointerBytes(0x3000),
		0x1010: pointerBytes(0),
		0x2000: append([]byte("alpha"), 0),
		0x3000: append([]byte("beta"), 0),
	}
	ctx := stringArrayContext(reader)

	if got := decodeStringArray(ctx, 0x1000, "argv"); got != `["alpha", "beta"]` {
		t.Fatalf("decodeStringArray(argv) = %q", got)
	}
	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000 /* 2 vars */" {
		t.Fatalf("decodeStringArray(envp) = %q", got)
	}
}

func TestDecodeStringArrayUsesSingularVar(t *testing.T) {
	reader := mapMemoryReader{
		0x1000: pointerBytes(0x2000),
		0x1008: pointerBytes(0),
		0x2000: append([]byte("VALUE=1"), 0),
	}
	ctx := stringArrayContext(reader)

	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000 /* 1 var */" {
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

func TestDecodeStringArrayAbbreviatesAfter32Elements(t *testing.T) {
	reader := mapMemoryReader{
		0x2000: append([]byte("x"), 0),
	}
	for i := 0; i < 33; i++ {
		reader[0x1000+uint64(i*8)] = pointerBytes(0x2000)
	}
	reader[0x1000+33*8] = pointerBytes(0)
	ctx := stringArrayContext(reader)

	want := "[" + strings.TrimSuffix(strings.Repeat(`"x", `, 32), ", ") + ", ...]"
	if got := decodeStringArray(ctx, 0x1000, "argv"); got != want {
		t.Fatalf("decodeStringArray(argv) = %q, want %q", got, want)
	}
}

func TestDecodeStringArrayMarksUnterminatedEnv(t *testing.T) {
	reader := mapMemoryReader{
		0x1000: pointerBytes(0x2000),
		0x2000: append([]byte("VALUE=1"), 0),
	}
	ctx := stringArrayContext(reader)

	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000 /* 1 var, unterminated */" {
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
	ctx.StrArgBuf = buf

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
	ctx.StrArgBuf = buf

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
	ctx.StrArgBuf = buf
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
	ctx.StrArgBuf = buf

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
	ctx.StrArgBuf = buf
	ctx.Opts.StringLimit = 40

	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	want := `["` + values[0] + `", "` + strings.Repeat("b", 40) + `"...]`
	if !ok || got != want {
		t.Fatalf("decode -s40 argv snapshot = %q, %v; want %q", got, ok, want)
	}
}
