package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func pointerBytes(ptr uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, ptr)
	return data
}

func stringArrayContext() *Context {
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
	ctx := stringArrayContext()

	if got := decodeStringArray(ctx, 0x1000, "argv"); got != "0x1000" {
		t.Fatalf("decodeStringArray(argv) = %q", got)
	}
	if got := decodeStringArray(ctx, 0x1000, "envp"); got != "0x1000" {
		t.Fatalf("decodeStringArray(envp) = %q", got)
	}
}

func TestDecodeStringArrayReportsUnreadablePointer(t *testing.T) {
	ctx := stringArrayContext()

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

	ctx := stringArrayContext()
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

	ctx := stringArrayContext()
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

	ctx := stringArrayContext()
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])
	cliOptionsForTest(ctx).Verbose = true

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

	ctx := stringArrayContext()
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])

	wantShort := "[" + strings.TrimSuffix(strings.Repeat(`"x", `, 32), ", ") + ", ...]"
	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	if !ok || got != wantShort {
		t.Fatalf("decode default argv snapshot = %q, %v; want %q", got, ok, wantShort)
	}

	cliOptionsForTest(ctx).Verbose = true
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

	ctx := stringArrayContext()
	setExecPayloadSnapshot(ctx, buf[execSnapshotOffset:])
	cliOptionsForTest(ctx).StringLimit = 40

	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	want := `["` + values[0] + `", "` + strings.Repeat("b", 40) + `"...]`
	if !ok || got != want {
		t.Fatalf("decode -s40 argv snapshot = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeExecIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	ctx := stringArrayContext()
	ctx.ProbeRetEnter = 0

	res := Result{}
	got, ok := decodeStringArrayPointer(ctx, 2, "const char *const *", "argv", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeStringArrayPointer(exec without section) = %q, %v; want pointer fallback", got, ok)
	}
}
