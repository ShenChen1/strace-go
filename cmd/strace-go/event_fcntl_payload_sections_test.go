package main

import (
	"bytes"
	"testing"
)

func TestJSONSyscallEventIncludesFcntlPayloadSections(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint16
		args      [6]uint64
		ret       int64
		wants     []wantFcntlJSONPayloadSection
	}{
		{
			name:      "F_SETLK enter flock",
			eventType: bpfEventTypeEnter,
			args:      [6]uint64{3, 6, 0x1000},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x11}, fcntlFlockPayloadSize)},
			},
		},
		{
			name:      "F_GETLK exit flock",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{3, 5, 0x2000},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x22}, fcntlFlockPayloadSize)},
				{"out", fcntlFlockPayloadSize, bytes.Repeat([]byte{0x33}, fcntlFlockPayloadSize)},
			},
		},
		{
			name:      "F_GETOWN_EX exit owner",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{3, 16, 0x3000},
			wants: []wantFcntlJSONPayloadSection{
				{"in", fcntlSmallPayloadSize, bytes.Repeat([]byte{0x44}, fcntlSmallPayloadSize)},
				{"out", fcntlSmallPayloadSize, bytes.Repeat([]byte{0x55}, fcntlSmallPayloadSize)},
			},
		},
		{
			name:      "F_GETFD has no pointer payload",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{3, 1, 0},
			ret:       1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloadTLVBytesForTest(t, fcntlJSONTLVSections(tt.args[2], tt.wants)...)
			ev := newJSONSyscallEventFromTLVForTest(t, "fcntl", tt.eventType, tt.args, tt.ret, payload)
			assertFcntlJSONPayloadSections(t, ev.PayloadSections, tt.wants, tt.args[2])
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
