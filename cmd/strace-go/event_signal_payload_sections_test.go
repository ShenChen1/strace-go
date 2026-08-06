package main

import (
	"bytes"
	"testing"
)

func TestJSONSyscallEventIncludesSignalPayloadSections(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint16
		args      [6]uint64
		ret       int64
		wants     []wantSignalJSONPayloadSection
	}{
		{
			name:      "rt_sigprocmask",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{0, 0x1000, 0x2000, 8},
			wants: []wantSignalJSONPayloadSection{
				{"struct", "in", 1, 0x1000, signalSigsetPayloadSize, bytes.Repeat([]byte{0x11}, signalSigsetPayloadSize)},
				{"struct", "out", 2, 0x2000, signalSigsetPayloadSize, bytes.Repeat([]byte{0x22}, signalSigsetPayloadSize)},
			},
		},
		{
			name:      "rt_sigaction",
			eventType: bpfEventTypeExit,
			args:      [6]uint64{2, 0x3000, 0x4000, 8},
			wants: []wantSignalJSONPayloadSection{
				{"struct", "in", 1, 0x3000, signalSigactionPayloadSize, bytes.Repeat([]byte{0x33}, signalSigactionPayloadSize)},
				{"struct", "out", 2, 0x4000, signalSigactionPayloadSize, bytes.Repeat([]byte{0x44}, signalSigactionPayloadSize)},
			},
		},
		{
			name:      "rt_sigsuspend",
			eventType: bpfEventTypeEnter,
			args:      [6]uint64{0x5000, 8},
			wants: []wantSignalJSONPayloadSection{
				{"struct", "in", 0, 0x5000, signalSigsetPayloadSize, bytes.Repeat([]byte{0x55}, signalSigsetPayloadSize)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloadTLVBytesForTest(t, signalJSONTLVSections(tt.wants)...)
			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, tt.eventType, tt.args, tt.ret, payload)
			assertSignalJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

type wantSignalJSONPayloadSection struct {
	kind      string
	direction string
	argIndex  int
	userPtr   uint64
	userLen   uint32
	data      []byte
}

func signalJSONTLVSections(wants []wantSignalJSONPayloadSection) []payloadTLVTestSection {
	sections := make([]payloadTLVTestSection, 0, len(wants))
	for _, want := range wants {
		sections = append(sections, payloadTLVTestSection{
			kind:    signalJSONTLVKind(want.kind),
			flags:   signalJSONTLVFlags(want.direction),
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: want.userLen,
			data:    want.data,
		})
	}
	return sections
}

func assertSignalJSONPayloadSections(t *testing.T, got []jsonPayloadSection, want []wantSignalJSONPayloadSection) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertSignalJSONPayloadSection(t, got[i], want[i])
	}
}

func assertSignalJSONPayloadSection(t *testing.T, got jsonPayloadSection, want wantSignalJSONPayloadSection) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("signal section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("signal section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != want.userLen || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("signal section lengths = %+v, want %+v", got, want)
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, want.data) {
		t.Fatalf("signal section data = %v, want %v", data, want.data)
	}
}

func signalJSONTLVKind(kind string) uint16 {
	if kind == "struct" {
		return payloadTLVKindStruct
	}
	return 0
}

func signalJSONTLVFlags(direction string) uint16 {
	if direction == "out" {
		return payloadTLVFlagDirectionOut
	}
	return 0
}
