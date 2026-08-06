package main

import (
	"bytes"
	"testing"
)

func TestJSONSyscallEventIncludesClone3PayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x44}, 88)
	args := [6]uint64{0x1000, uint64(len(wantData))}
	payload := payloadTLVBytesForTest(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     0,
		userPtr: 0x1000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "clone3", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "struct" || section.Direction != "in" || section.ArgIndex != 0 {
		t.Fatalf("clone3 section metadata = %+v", section)
	}
	if section.UserPtr != 0x1000 {
		t.Fatalf("clone3 section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("clone3 section lengths = %+v, want %d", section, len(wantData))
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("clone3 section data length = %d, want %d", len(data), len(wantData))
	}
}
