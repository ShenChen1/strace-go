package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesClone3PayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x44}, 88)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, uint64(len(wantData))},
		DataLen:       uint32(len(wantData)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], wantData)

	scMeta := meta.Syscall{Name: "clone3"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "struct" || section.Direction != "in" || section.ArgIndex != 0 {
		t.Fatalf("clone3 section metadata = %+v", section)
	}
	if section.Offset != handler.BpfEnterArgOffset || section.UserPtr != 0x1000 {
		t.Fatalf("clone3 section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("clone3 section lengths = %+v, want %d", section, len(wantData))
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("clone3 section data length = %d, want %d", len(data), len(wantData))
	}
}
