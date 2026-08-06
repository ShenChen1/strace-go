package main

import (
	"encoding/binary"
	"testing"
)

const archPrctlPayloadOutSize = 8

func TestJSONSyscallEventIncludesArchPrctlPayloadSection(t *testing.T) {
	wantData := archPrctlJSONWord(0x1234)
	args := [6]uint64{0x1003, 0x2000}
	payload := payloadTLVBytesForTest(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: archPrctlPayloadOutSize,
		data:    wantData,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "arch_prctl", bpfEventTypeExit, args, 0, payload)
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != 1 {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.UserPtr != 0x2000 {
		t.Fatalf("section bounds = %+v", section)
	}
	if section.UserLen != archPrctlPayloadOutSize || section.CopiedLen != archPrctlPayloadOutSize {
		t.Fatalf("section lengths = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != string(wantData) {
		t.Fatalf("section data = %v, want %v", got, wantData)
	}
}

func archPrctlJSONWord(value uint64) []byte {
	data := make([]byte, archPrctlPayloadOutSize)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
