package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesArchPrctlPayloadSection(t *testing.T) {
	wantData := archPrctlJSONWord(0x1234)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: archPrctlPayloadOutSize,
		data:    wantData,
	})
	eventRaw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		EventFlags:   bpfEventFlagPayloadTLV,
		Args:         [6]uint64{0x1003, 0x2000},
		Ret:          0,
		DataLen:      uint32(len(payload)),
		ProbeRetExit: 0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "arch_prctl"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
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
