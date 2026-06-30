package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesSendfileOffsetPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{4, 5, 0x1000, 99},
		Ret:           99,
		DataLen:       handler.BpfExitArgOffset + offsetPointerPayloadSize,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset:], offsetJSONWord(10))
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], offsetJSONWord(20))

	scMeta := meta.Syscall{Name: "sendfile"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOffsetSection(t, ev.PayloadSections[0], 2, "in", handler.BpfMiscArgOffset, 0x1000, offsetJSONWord(10))
	assertOffsetSection(t, ev.PayloadSections[1], 2, "out", handler.BpfExitArgOffset, 0x1000, offsetJSONWord(20))
}

func TestJSONSyscallEventIncludesCopyFileRangeOffsetPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{4, 0x1000, 5, 0x2000, 99, 0},
		DataLen:       handler.BpfMiscArgOffset + offsetPointerPayloadSize*2,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset:], offsetJSONWord(11))
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset+8:], offsetJSONWord(22))

	scMeta := meta.Syscall{Name: "copy_file_range"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertOffsetSection(t, ev.PayloadSections[0], 1, "in", handler.BpfMiscArgOffset, 0x1000, offsetJSONWord(11))
	assertOffsetSection(t, ev.PayloadSections[1], 3, "in", handler.BpfMiscArgOffset+8, 0x2000, offsetJSONWord(22))
}

func assertOffsetSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	direction string,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != "struct" || section.Direction != direction || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.Offset != uint32(offset) || section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != offsetPointerPayloadSize || section.CopiedLen != offsetPointerPayloadSize {
		t.Fatalf("section lengths = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(wantData) {
		t.Fatalf("section data = %v, want %v", got, wantData)
	}
}

func offsetJSONWord(value uint64) []byte {
	data := make([]byte, offsetPointerPayloadSize)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
