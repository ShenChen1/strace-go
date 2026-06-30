package handler

import (
	"encoding/binary"
	"testing"
)

func TestDecodeExecStringArrayUsesPayloadSection(t *testing.T) {
	snapshot := makeExecPayloadSnapshot([]string{"first", "second"}, []string{"A=1"})
	ctx := stringArrayContext(mapMemoryReader{})
	ctx.Opts.Verbose = true
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindExecArgs,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x1000,
			UserLen:   uint32(len(snapshot)),
			CopiedLen: uint32(len(snapshot)),
			ProbeRet:  0,
			Data:      snapshot,
		},
	}

	got, ok := decodeExecStringArraySnapshot(ctx, 0x1000, "argv")
	if !ok || got != `["first", "second"]` {
		t.Fatalf("decode argv payload section = %q, %v", got, ok)
	}
	got, ok = decodeExecStringArraySnapshot(ctx, 0x4000, "envp")
	if !ok || got != `["A=1"]` {
		t.Fatalf("decode envp payload section = %q, %v", got, ok)
	}
}

func makeExecPayloadSnapshot(argv []string, envp []string) []byte {
	size := execSnapshotHeaderSize + (execArgSnapshotCount+execEnvSnapshotCount)*execArgSnapshotSize
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[0:4], execSnapshotMagic)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(argv)))
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(envp)))
	writeExecPayloadRecords(buf, execSnapshotHeaderSize, argv, 0x2000)
	envOffset := execSnapshotHeaderSize + execArgSnapshotCount*execArgSnapshotSize
	writeExecPayloadRecords(buf, envOffset, envp, 0x4000)
	return buf
}

func writeExecPayloadRecords(buf []byte, baseOffset int, values []string, basePtr uint64) {
	for i, value := range values {
		offset := baseOffset + i*execArgSnapshotSize
		record := buf[offset : offset+execArgSnapshotSize]
		binary.LittleEndian.PutUint64(record[0:8], basePtr+uint64(i)*0x100)
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(value)+1))
		copy(record[execArgDataOffset:], value)
		record[execArgDataOffset+len(value)] = 0
	}
}
