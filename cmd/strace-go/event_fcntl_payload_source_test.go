package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareFcntlRule(t *testing.T) {
	tests := []struct {
		name  string
		raw   bpfEvent
		wants []wantFcntlSourcePayloadSection
	}{
		{
			name: "set lock enter flock",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{3, 6, 0x1000},
				ProbeRetEnter: 0,
			},
			wants: []wantFcntlSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, offset: handler.BpfEnterArgOffset, data: bytes.Repeat([]byte{0x11}, fcntlFlockPayloadSize)},
			},
		},
		{
			name: "get lock exit flock",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{3, 5, 0x2000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantFcntlSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, offset: handler.BpfEnterArgOffset, data: bytes.Repeat([]byte{0x22}, fcntlFlockPayloadSize)},
				{direction: handler.PayloadDirectionOut, offset: handler.BpfExitArgOffset, data: bytes.Repeat([]byte{0x33}, fcntlFlockPayloadSize)},
			},
		},
		{
			name: "get owner exit small struct",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{3, 16, 0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantFcntlSourcePayloadSection{
				{direction: handler.PayloadDirectionIn, offset: handler.BpfEnterArgOffset, data: bytes.Repeat([]byte{0x44}, fcntlSmallPayloadSize)},
				{direction: handler.PayloadDirectionOut, offset: handler.BpfExitArgOffset, data: bytes.Repeat([]byte{0x55}, fcntlSmallPayloadSize)},
			},
		},
		{
			name: "no pointer payload",
			raw: bpfEvent{
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
			raw := tt.raw
			data := make([]byte, handler.BpfExitArgOffset+fcntlFlockPayloadSize)
			putFcntlSourcePayloads(data, tt.wants)
			event := payloadEvent{
				raw: &raw,
				source: staticPayloadSource{
					args: raw.Args,
					data: data,
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "fcntl"})

			assertFcntlSourcePayloadSections(t, sections, tt.wants, raw.Args[2])
		})
	}
}

type wantFcntlSourcePayloadSection struct {
	direction handler.PayloadDirection
	offset    int
	data      []byte
}

func putFcntlSourcePayloads(data []byte, wants []wantFcntlSourcePayloadSection) {
	for _, want := range wants {
		copy(data[want.offset:], want.data)
	}
}

func assertFcntlSourcePayloadSections(
	t *testing.T,
	got []handler.PayloadSection,
	want []wantFcntlSourcePayloadSection,
	userPtr uint64,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertFcntlSourcePayloadSection(t, got[i], want[i], userPtr)
	}
}

func assertFcntlSourcePayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	want wantFcntlSourcePayloadSection,
	userPtr uint64,
) {
	t.Helper()
	if got.Kind != handler.PayloadKindStruct || got.Direction != want.direction || got.ArgIndex != 2 {
		t.Fatalf("fcntl section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != uint32(want.offset) || got.UserPtr != userPtr {
		t.Fatalf("fcntl section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("fcntl section lengths = %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("fcntl section data = %v, want %v", got.Data, want.data)
	}
}
