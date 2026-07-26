package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesSendfileOffsetPayloadSections(t *testing.T) {
	enterData := offsetJSONWord(10)
	exitData := offsetJSONWord(20)
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeExit,
		Args:      [6]uint64{4, 5, 0x1000, 99},
		Ret:       99,
	}
	setJSONTestTLVPayload(t, eventRaw,
		offsetJSONTLVStruct(2, 0, 0x1000, enterData),
		offsetJSONTLVStruct(2, payloadTLVFlagDirectionOut, 0x1000, exitData),
	)

	scMeta := meta.Syscall{Name: "sendfile"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOffsetSection(t, ev.PayloadSections[0], 2, "in", 0x1000, enterData)
	assertOffsetSection(t, ev.PayloadSections[1], 2, "out", 0x1000, exitData)
}

func TestJSONSyscallEventIncludesCopyFileRangeOffsetPayloadSections(t *testing.T) {
	inData := offsetJSONWord(11)
	outData := offsetJSONWord(22)
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeEnter,
		Args:      [6]uint64{4, 0x1000, 5, 0x2000, 99, 0},
	}
	setJSONTestTLVPayload(t, eventRaw,
		offsetJSONTLVStruct(1, 0, 0x1000, inData),
		offsetJSONTLVStruct(3, 0, 0x2000, outData),
	)

	scMeta := meta.Syscall{Name: "copy_file_range"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOffsetSection(t, ev.PayloadSections[0], 1, "in", 0x1000, inData)
	assertOffsetSection(t, ev.PayloadSections[1], 3, "in", 0x2000, outData)
}

func assertOffsetSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	direction string,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != "struct" || section.Direction != direction || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != offsetPointerPayloadSize || section.CopiedLen != offsetPointerPayloadSize {
		t.Fatalf("section lengths = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(wantData) {
		t.Fatalf("section data = %v, want %v", got, wantData)
	}
}

func offsetJSONTLVStruct(arg uint16, flags uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   flags,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

func offsetJSONWord(value uint64) []byte {
	data := make([]byte, offsetPointerPayloadSize)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
