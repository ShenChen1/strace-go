package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionRegistryPrefersExplicitStructuredRules(t *testing.T) {
	if _, ok := payloadSourceSectionRules["stat"]; !ok {
		t.Fatal("stat payload rule is not explicitly registered in the source-aware registry")
	}

	wantData := bytes.Repeat([]byte{0x42}, statPayloadStructSize)
	eventRaw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0x1000, 0x2000},
		Ret:          0,
		DataLen:      uint32(handler.BpfExitArgOffset + statPayloadStructSize),
		ProbeRetExit: 0,
	}
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], wantData)

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "stat"})
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindStruct || section.ArgIndex != 1 {
		t.Fatalf("stat section = %+v, want struct arg 1", section)
	}
	if !bytes.Equal(section.Data, wantData) {
		t.Fatalf("stat data length = %d, want %d", len(section.Data), len(wantData))
	}
}

func TestPayloadSectionRegistryFallsBackToSimplePathRules(t *testing.T) {
	if _, ok := payloadSectionRules["chdir"]; ok {
		t.Fatal("chdir should use the simple path fallback, not an explicit payload rule")
	}

	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000},
		DataLen:       uint32(len("/tmp/a") + 1),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("/tmp/a\x00"))

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "chdir"})
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.ArgIndex != 0 {
		t.Fatalf("chdir section = %+v, want string arg 0", section)
	}
	if string(section.Data) != "/tmp/a\x00" {
		t.Fatalf("chdir data = %q, want /tmp/a", string(section.Data))
	}
}
