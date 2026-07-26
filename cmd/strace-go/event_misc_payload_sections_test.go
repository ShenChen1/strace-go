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
		flags     uint16
		size      int
	}{
		{name: "uname", eventType: bpfEventTypeExit, args: [6]uint64{0x1000}, argIndex: 0, direction: "out", flags: payloadTLVFlagDirectionOut, size: utsnamePayloadStructSize},
		{name: "sysinfo", eventType: bpfEventTypeExit, args: [6]uint64{0x2000}, argIndex: 0, direction: "out", flags: payloadTLVFlagDirectionOut, size: sysinfoPayloadStructSize},
		{name: "getrlimit", eventType: bpfEventTypeExit, args: [6]uint64{7, 0x3000}, argIndex: 1, direction: "out", flags: payloadTLVFlagDirectionOut, size: rlimitPayloadStructSize},
		{name: "setrlimit", eventType: bpfEventTypeEnter, args: [6]uint64{7, 0x4000}, argIndex: 1, direction: "in", size: rlimitPayloadStructSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := bytes.Repeat([]byte{0x5a}, tt.size)
			payload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   tt.flags,
				arg:     uint16(tt.argIndex),
				userPtr: tt.args[tt.argIndex],
				userLen: uint32(tt.size),
				data:    wantData,
			})
			eventRaw := &bpfEvent{
				EventType:     tt.eventType,
				EventFlags:    bpfEventFlagPayloadTLV,
				Args:          tt.args,
				Ret:           0,
				DataLen:       uint32(len(payload)),
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			}
			copy(eventRaw.StrArg[:], payload)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertMiscStructSection(t, ev.PayloadSections[0], tt.argIndex, tt.direction, tt.size, wantData)
		})
	}
}

func TestJSONSyscallEventIncludesPrlimitPayloadSections(t *testing.T) {
	newLimit := bytes.Repeat([]byte{0x11}, rlimitPayloadStructSize)
	oldLimit := bytes.Repeat([]byte{0x22}, rlimitPayloadStructSize)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     2,
		userPtr: 0x3000,
		userLen: rlimitPayloadStructSize,
		data:    newLimit,
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     3,
		userPtr: 0x4000,
		userLen: rlimitPayloadStructSize,
		data:    oldLimit,
	})...)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		EventFlags:    bpfEventFlagPayloadTLV,
		Args:          [6]uint64{101, 7, 0x3000, 0x4000},
		Ret:           0,
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "prlimit64"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertMiscStructSection(t, ev.PayloadSections[0], 2, "in", rlimitPayloadStructSize, newLimit)
	assertMiscStructSection(t, ev.PayloadSections[1], 3, "out", rlimitPayloadStructSize, oldLimit)
}

func assertMiscStructSection(
	t *testing.T,
	section jsonPayloadSection,
	argIndex int,
	direction string,
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
