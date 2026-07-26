package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesRobustListPayloadSections(t *testing.T) {
	headData := robustListJSONWord(0xfeedface)
	lenData := robustListJSONWord(24)
	eventRaw := &bpfEvent{
		EventType: bpfEventTypeExit,
		Args:      [6]uint64{0, 0x1000, 0x2000},
		Ret:       0,
	}
	setJSONTestTLVPayload(t, eventRaw,
		robustListJSONTLVStruct(1, 0x1000, headData),
		robustListJSONTLVStruct(2, 0x2000, lenData),
	)

	scMeta := meta.Syscall{Name: "get_robust_list"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertRobustListSection(t, ev.PayloadSections[0], 1, 0x1000, headData)
	assertRobustListSection(t, ev.PayloadSections[1], 2, 0x2000, lenData)
}

func assertRobustListSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.UserPtr != userPtr {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != robustListPayloadWordSize || section.CopiedLen != robustListPayloadWordSize {
		t.Fatalf("section lengths = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(wantData) {
		t.Fatalf("section data = %v, want %v", got, wantData)
	}
}

func robustListJSONTLVStruct(arg uint16, userPtr uint64, data []byte) payloadTLVTestSection {
	return payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	}
}

func robustListJSONWord(value uint64) []byte {
	data := make([]byte, robustListPayloadWordSize)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
