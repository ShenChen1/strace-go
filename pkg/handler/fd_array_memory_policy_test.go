package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestDecodePipeFDArrayUsesPayloadStructSection(t *testing.T) {
	ctx := &Context{
		Pid:     101,
		Tid:     102,
		Ret:     0,
		Args:    [6]uint64{0x1000},
		ScMeta:  meta.Syscall{Name: "pipe"},
		Decoder: event.NewDecoder(),
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionOut,
				ArgIndex:  0,
				UserPtr:   0x1000,
				UserLen:   fdArrayPayloadSize,
				CopiedLen: fdArrayPayloadSize,
				ProbeRet:  0,
				Data:      fdArrayData(21, 22),
			},
		},
	}
	res := Result{}

	got, ok := decodeIntPointer(ctx, 0, "int *", "pipefd", 0x1000, &res)
	if !ok || got != "[21, 22]" {
		t.Fatalf("decodeIntPointer(pipe) = %q, %v", got, ok)
	}
}

func TestDecodePipeFDArrayFallsBackToPointerWithoutSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:     101,
		Tid:     102,
		Ret:     0,
		Args:    [6]uint64{0x1000},
		ScMeta:  meta.Syscall{Name: "pipe"},
		Decoder: event.NewDecoder(),
	}
	res := Result{}

	got, ok := decodeIntPointer(ctx, 0, "int *", "pipefd", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeIntPointer fallback = %q, %v; want pointer", got, ok)
	}
}

func TestDecodePipeFDArrayIgnoresLegacyFixedSnapshot(t *testing.T) {
	ctx := &Context{
		Pid:          101,
		Tid:          102,
		Ret:          0,
		Args:         [6]uint64{0x1000},
		ScMeta:       meta.Syscall{Name: "pipe"},
		Decoder:      event.NewDecoder(),
		ProbeRetExit: 0,
		StrArgBuf:    make([]byte, BpfExitArgOffset+fdArrayPayloadSize),
	}
	putSmallSnapshot(ctx, BpfExitArgOffset, fdArrayData(21, 22))
	res := Result{}

	got, ok := decodeIntPointer(ctx, 0, "int *", "pipefd", 0x1000, &res)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeIntPointer legacy snapshot = %q, %v; want pointer", got, ok)
	}
}

func fdArrayData(first uint32, second uint32) []byte {
	data := make([]byte, fdArrayPayloadSize)
	binary.LittleEndian.PutUint32(data[0:4], first)
	binary.LittleEndian.PutUint32(data[4:8], second)
	return data
}
