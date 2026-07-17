package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesMiscStructPayloadSections(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint16
		args      [6]uint64
		argIndex  int
		direction string
		offset    int
		size      int
	}{
		{name: "uname", eventType: bpfEventTypeExit, args: [6]uint64{0x1000}, argIndex: 0, direction: "out", offset: payloadExitArgOffset, size: utsnamePayloadStructSize},
		{name: "sysinfo", eventType: bpfEventTypeExit, args: [6]uint64{0x2000}, argIndex: 0, direction: "out", offset: payloadExitArgOffset, size: sysinfoPayloadStructSize},
		{name: "getrlimit", eventType: bpfEventTypeExit, args: [6]uint64{7, 0x3000}, argIndex: 1, direction: "out", offset: payloadExitArgOffset, size: rlimitPayloadStructSize},
		{name: "setrlimit", eventType: bpfEventTypeEnter, args: [6]uint64{7, 0x4000}, argIndex: 1, direction: "in", offset: payloadEnterArgOffset, size: rlimitPayloadStructSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := bytes.Repeat([]byte{0x5a}, tt.size)
			eventRaw := &bpfEvent{
				EventType:     tt.eventType,
				Args:          tt.args,
				Ret:           0,
				DataLen:       uint32(tt.offset + tt.size),
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			}
			copy(eventRaw.StrArg[tt.offset:], wantData)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertMiscStructSection(t, ev.PayloadSections[0], tt.argIndex, tt.direction, tt.offset, tt.size, wantData)
		})
	}
}

func TestJSONSyscallEventIncludesPrlimitPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{101, 7, 0x3000, 0x4000},
		Ret:           0,
		DataLen:       payloadExitArgOffset + rlimitPayloadStructSize,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], bytes.Repeat([]byte{0x11}, rlimitPayloadStructSize))
	copy(eventRaw.StrArg[payloadExitArgOffset:], bytes.Repeat([]byte{0x22}, rlimitPayloadStructSize))

	scMeta := meta.Syscall{Name: "prlimit64"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertMiscStructSection(t, ev.PayloadSections[0], 2, "in", payloadEnterArgOffset, rlimitPayloadStructSize, bytes.Repeat([]byte{0x11}, rlimitPayloadStructSize))
	assertMiscStructSection(t, ev.PayloadSections[1], 3, "out", payloadExitArgOffset, rlimitPayloadStructSize, bytes.Repeat([]byte{0x22}, rlimitPayloadStructSize))
}

func assertMiscStructSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	direction string,
	offset int,
	size int,
	wantData []byte,
) {
	t.Helper()
	if section.Kind != "struct" || section.Direction != direction || section.ArgIndex != argIndex {
		t.Fatalf("section metadata = %+v", section)
	}
	if section.UserLen != uint32(size) || section.CopiedLen != uint32(size) {
		t.Fatalf("section bounds = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
		t.Fatalf("section data = %v, want %v", got, wantData)
	}
}
