package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwarePrctlRule(t *testing.T) {
	tests := []struct {
		name  string
		raw   bpfEvent
		wants []wantPrctlSourcePayloadSection
	}{
		{
			name: "set name",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{15, 0x1000},
				ProbeRetEnter: 0,
			},
			wants: []wantPrctlSourcePayloadSection{
				{kind: handler.PayloadKindString, direction: handler.PayloadDirectionIn, offset: payloadEnterArgOffset, userPtr: 0x1000, data: []byte("worker\x00")},
			},
		},
		{
			name: "get name",
			raw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{16, 0x2000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlSourcePayloadSection{
				{kind: handler.PayloadKindString, direction: handler.PayloadDirectionOut, offset: payloadExitArgOffset, userPtr: 0x2000, data: []byte("worker\x00")},
			},
		},
		{
			name: "get child subreaper",
			raw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{37, 0x3000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlSourcePayloadSection{
				{kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionOut, offset: payloadExitArgOffset, userPtr: 0x3000, data: prctlJSONUint32(1)},
			},
		},
		{
			name: "no pointer payload",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{2, 15},
				ProbeRetEnter: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.raw
			data := make([]byte, payloadExitArgOffset+prctlNamePayloadSize)
			putPrctlSourcePayloads(data, tt.wants)
			event := payloadEvent{
				raw: &raw,
				source: staticPayloadSource{
					args: raw.Args,
					data: data,
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "prctl"})

			assertPrctlSourcePayloadSections(t, sections, tt.wants)
		})
	}
}

type wantPrctlSourcePayloadSection struct {
	kind      handler.PayloadKind
	direction handler.PayloadDirection
	offset    int
	userPtr   uint64
	data      []byte
}

func putPrctlSourcePayloads(data []byte, wants []wantPrctlSourcePayloadSection) {
	for _, want := range wants {
		copy(data[want.offset:], want.data)
	}
}

func assertPrctlSourcePayloadSections(
	t *testing.T,
	got []handler.PayloadSection,
	want []wantPrctlSourcePayloadSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertPrctlSourcePayloadSection(t, got[i], want[i])
	}
}

func assertPrctlSourcePayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	want wantPrctlSourcePayloadSection,
) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != 1 {
		t.Fatalf("prctl section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != uint32(want.offset) || got.UserPtr != want.userPtr {
		t.Fatalf("prctl section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("prctl section lengths = %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("prctl section data = %v, want %v", got.Data, want.data)
	}
}
