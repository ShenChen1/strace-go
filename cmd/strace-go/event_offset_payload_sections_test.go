package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesSendfileOffsetPayloadSections(t *testing.T) {
	enterData := offsetJSONWord(10)
	exitData := offsetJSONWord(20)
	payload := offsetJSONTLVStruct(t, 2, 0, 0x1000, enterData)
	payload = append(payload, offsetJSONTLVStruct(t, 2, payloadTLVFlagDirectionOut, 0x1000, exitData)...)
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeExit,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{4, 5, 0x1000, 99},
		Ret:        99,
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

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
	payload := offsetJSONTLVStruct(t, 1, 0, 0x1000, inData)
	payload = append(payload, offsetJSONTLVStruct(t, 3, 0, 0x2000, outData)...)
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{4, 0x1000, 5, 0x2000, 99, 0},
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

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

func offsetJSONTLVStruct(t *testing.T, arg uint16, flags uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   flags,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}

func offsetJSONWord(value uint64) []byte {
	data := make([]byte, offsetPointerPayloadSize)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
