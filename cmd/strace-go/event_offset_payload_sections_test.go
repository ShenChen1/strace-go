package main

import (
	"encoding/binary"
	"testing"
)

const offsetPointerPayloadSize = 8

func TestJSONSyscallEventIncludesSendfileOffsetPayloadSections(t *testing.T) {
	enterData := offsetJSONWord(10)
	exitData := offsetJSONWord(20)
	args := [6]uint64{4, 5, 0x1000, 99}
	payload := payloadTLVBytesForTest(t,
		offsetJSONTLVStruct(2, 0, 0x1000, enterData),
		offsetJSONTLVStruct(2, payloadTLVFlagDirectionOut, 0x1000, exitData),
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "sendfile", bpfEventTypeExit, args, 99, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOffsetSection(t, ev.PayloadSections[0], 2, "in", 0x1000, enterData)
	assertOffsetSection(t, ev.PayloadSections[1], 2, "out", 0x1000, exitData)
}

func TestJSONSyscallEventIncludesCopyFileRangeOffsetPayloadSections(t *testing.T) {
	inData := offsetJSONWord(11)
	outData := offsetJSONWord(22)
	args := [6]uint64{4, 0x1000, 5, 0x2000, 99, 0}
	payload := payloadTLVBytesForTest(t,
		offsetJSONTLVStruct(1, 0, 0x1000, inData),
		offsetJSONTLVStruct(3, 0, 0x2000, outData),
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "copy_file_range", bpfEventTypeEnter, args, 0, payload)
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
