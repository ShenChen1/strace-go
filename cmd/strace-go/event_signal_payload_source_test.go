package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareSignalRules(t *testing.T) {
	tests := []struct {
		name  string
		raw   bpfEvent
		wants []wantSignalSourcePayloadSection
	}{
		{
			name: "rt_sigprocmask",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0, 0x1000, 0x2000, 8},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantSignalSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, argIndex: 1, offset: payloadEnterArgOffset, userPtr: 0x1000, data: bytes.Repeat([]byte{0x11}, signalSigsetPayloadSize)},
				{direction: handler.PayloadDirectionOut, argIndex: 2, offset: payloadExitArgOffset, userPtr: 0x2000, data: bytes.Repeat([]byte{0x22}, signalSigsetPayloadSize)},
			},
		},
		{
			name: "rt_sigaction",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{2, 0x3000, 0x4000, 8},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantSignalSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, argIndex: 1, offset: payloadEnterArgOffset, userPtr: 0x3000, data: bytes.Repeat([]byte{0x33}, signalSigactionPayloadSize)},
				{direction: handler.PayloadDirectionOut, argIndex: 2, offset: payloadExitArgOffset, userPtr: 0x4000, data: bytes.Repeat([]byte{0x44}, signalSigactionPayloadSize)},
			},
		},
		{
			name: "rt_sigsuspend",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x5000, 8},
				ProbeRetEnter: 0,
			},
			wants: []wantSignalSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, argIndex: 0, offset: payloadEnterArgOffset, userPtr: 0x5000, data: bytes.Repeat([]byte{0x55}, signalSigsetPayloadSize)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.raw
			data := make([]byte, payloadExitArgOffset+signalSigactionPayloadSize)
			putSignalSourcePayloads(data, tt.wants)
			event := payloadEvent{
				raw: &raw,
				source: staticPayloadSource{
					args: raw.Args,
					data: data,
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: tt.name})

			assertSignalSourcePayloadSections(t, sections, tt.wants)
		})
	}
}

type wantSignalSourcePayloadSection struct {
	direction handler.PayloadDirection
	argIndex  int
	offset    int
	userPtr   uint64
	data      []byte
}

func putSignalSourcePayloads(data []byte, wants []wantSignalSourcePayloadSection) {
	for _, want := range wants {
		copy(data[want.offset:], want.data)
	}
}

func assertSignalSourcePayloadSections(
	t *testing.T,
	got []handler.PayloadSection,
	want []wantSignalSourcePayloadSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertSignalSourcePayloadSection(t, got[i], want[i])
	}
}

func assertSignalSourcePayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	want wantSignalSourcePayloadSection,
) {
	t.Helper()
	if got.Kind != handler.PayloadKindStruct || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("signal section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("signal section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("signal section lengths = %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("signal section data = %v, want %v", got.Data, want.data)
	}
}
