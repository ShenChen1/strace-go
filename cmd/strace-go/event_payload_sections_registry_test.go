package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForEventUsesRawTLVStructSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x42}, statPayloadStructSize)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x2000},
		Ret:           0,
		ProbeRetExit:  0,
		ProbeRetEnter: -1,
	}
	setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})

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

func TestPayloadSectionsForEventUsesRawTLVStringSection(t *testing.T) {
	wantData := []byte("/tmp/a\x00")
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000},
		ProbeRetEnter: 0,
	}
	setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: 0x1000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})

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
