package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesArchPrctlPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0x1003, 0x2000},
		Ret:          0,
		DataLen:      handler.BpfExitArgOffset + archPrctlPayloadOutSize,
		ProbeRetExit: 0,
	}
	wantData := archPrctlJSONWord(0x1234)
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], wantData)

	scMeta := meta.Syscall{Name: "arch_prctl"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != 1 {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.Offset != handler.BpfExitArgOffset || section.UserPtr != 0x2000 {
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
