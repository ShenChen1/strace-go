package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesBpfAttrPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0, 0x1000, uint64(len(wantData))},
		DataLen:       uint32(len(wantData)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], wantData)

	scMeta := meta.Syscall{Name: "bpf"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 1 {
		t.Fatalf("bpf section metadata = %+v", section)
	}
	if section.Offset != handler.BpfEnterArgOffset || section.UserPtr != 0x1000 {
		t.Fatalf("bpf section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("bpf section lengths = %+v, want %d", section, len(wantData))
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("bpf section data length = %d, want %d", len(data), len(wantData))
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareBpfRule(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x7b}, 32)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0, 0x1000, uint64(len(wantData))},
		ProbeRetEnter: 0,
	}
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: wantData,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "bpf"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindBytes || section.Direction != handler.PayloadDirectionIn ||
		section.ArgIndex != 1 || section.UserPtr != 0x1000 {
		t.Fatalf("bpf section metadata = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("bpf section lengths = %+v", section)
	}
	if !bytes.Equal(section.Data, wantData) {
		t.Fatalf("bpf section data = %v, want %v", section.Data, wantData)
	}
}
