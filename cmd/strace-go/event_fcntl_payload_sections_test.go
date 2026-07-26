package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesFcntlPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantFcntlJSONPayloadSection
	}{
		{
			name: "F_SETLK enter flock",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{3, 6, 0x1000},
				ProbeRetEnter: 0,
			},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x11}, fcntlFlockPayloadSize)},
			},
		},
		{
			name: "F_GETLK exit flock",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{3, 5, 0x2000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x22}, fcntlFlockPayloadSize)},
				{"out", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x33}, fcntlFlockPayloadSize)},
			},
		},
		{
			name: "F_GETOWN_EX exit owner",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{3, 16, 0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlSmallPayloadSize, bytes.Repeat([]byte{0x44}, fcntlSmallPayloadSize)},
				{"out", fcntlSmallPayloadSize, bytes.Repeat([]byte{0x55}, fcntlSmallPayloadSize)},
			},
		},
		{
			name: "F_GETFD has no pointer payload",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{3, 1, 0},
				Ret:           1,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putFcntlJSONPayloads(t, &eventRaw, tt.wants)
			scMeta := meta.Syscall{Name: "fcntl"}
			ev := newJSONSyscallEvent(&eventRaw, scMeta, payloadSectionsForEvent(&eventRaw, scMeta))
			assertFcntlJSONPayloadSections(t, ev.PayloadSections, tt.wants, eventRaw.Args[2])
		})
	}
}

const (
	fcntlSmallPayloadSize = 8
	fcntlFlockPayloadSize = 32
)

type wantFcntlJSONPayloadSection struct {
	direction string
	size      uint32
	data      []byte
}

func putFcntlJSONPayloads(t *testing.T, eventRaw *bpfEvent, wants []wantFcntlJSONPayloadSection) {
	t.Helper()
	if len(wants) == 0 {
		return
	}
	setJSONTestTLVPayload(t, eventRaw, fcntlJSONTLVSections(eventRaw.Args[2], wants)...)
}

func fcntlJSONTLVSections(userPtr uint64, wants []wantFcntlJSONPayloadSection) []payloadTLVTestSection {
	sections := make([]payloadTLVTestSection, 0, len(wants))
	for _, want := range wants {
		sections = append(sections, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   fcntlJSONTLVFlags(want.direction),
			arg:     2,
			userPtr: userPtr,
			userLen: want.size,
			data:    want.data,
		})
	}
	return sections
}

func assertFcntlJSONPayloadSections(
	t *testing.T,
	got []jsonPayloadSection,
	want []wantFcntlJSONPayloadSection,
	userPtr uint64,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertFcntlJSONPayloadSection(t, got[i], want[i], userPtr)
	}
}

func assertFcntlJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantFcntlJSONPayloadSection,
	userPtr uint64,
) {
	t.Helper()
	if got.Kind != "struct" || got.Direction != want.direction || got.ArgIndex != 2 {
		t.Fatalf("fcntl section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("fcntl section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != want.size || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("fcntl section lengths = %+v, want %+v", got, want)
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, want.data) {
		t.Fatalf("fcntl section data = %v, want %v", data, want.data)
	}
}

func fcntlJSONTLVFlags(direction string) uint16 {
	if direction == "out" {
		return payloadTLVFlagDirectionOut
	}
	return 0
}
