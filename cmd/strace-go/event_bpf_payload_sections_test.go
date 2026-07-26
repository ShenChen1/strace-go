package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesBpfAttrPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{0, 0x1000, uint64(len(wantData))},
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "bpf"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 1 {
		t.Fatalf("bpf section metadata = %+v", section)
	}
	if section.UserPtr != 0x1000 {
		t.Fatalf("bpf section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("bpf section lengths = %+v, want %d", section, len(wantData))
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("bpf section data length = %d, want %d", len(data), len(wantData))
	}
}
