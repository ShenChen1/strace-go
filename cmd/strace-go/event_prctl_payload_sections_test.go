package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesPrctlPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantPrctlJSONPayloadSection
	}{
		{
			name: "PR_SET_NAME",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{15, 0x1000},
				ProbeRetEnter: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"string", "in", 0x1000, []byte("worker\x00")},
			},
		},
		{
			name: "PR_GET_NAME",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{16, 0x2000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"string", "out", 0x2000, []byte("worker\x00")},
			},
		},
		{
			name: "PR_GET_CHILD_SUBREAPER",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{37, 0x3000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"struct", "out", 0x3000, prctlJSONUint32(1)},
			},
		},
		{
			name: "PR_SET_PDEATHSIG has no pointer payload",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{2, 15},
				ProbeRetEnter: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putPrctlJSONPayloads(t, &eventRaw, tt.wants)
			scMeta := meta.Syscall{Name: "prctl"}
			ev := newJSONSyscallEvent(&eventRaw, scMeta, payloadSectionsForEvent(&eventRaw, scMeta))
			assertPrctlJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

type wantPrctlJSONPayloadSection struct {
	kind      string
	direction string
	userPtr   uint64
	data      []byte
}

func putPrctlJSONPayloads(t *testing.T, eventRaw *bpfEvent, wants []wantPrctlJSONPayloadSection) {
	t.Helper()
	if len(wants) == 0 {
		eventRaw.DataLen = 0
		return
	}
	eventRaw.EventFlags |= bpfEventFlagPayloadTLV
	payload := prctlJSONTLVPayload(t, wants)
	eventRaw.DataLen = uint32(len(payload))
	copy(eventRaw.StrArg[:], payload)
}

func prctlJSONTLVPayload(t *testing.T, wants []wantPrctlJSONPayloadSection) []byte {
	t.Helper()
	var payload []byte
	for _, want := range wants {
		payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    prctlJSONTLVKind(want.kind),
			flags:   prctlJSONTLVFlags(want.direction),
			arg:     1,
			userPtr: want.userPtr,
			userLen: uint32(len(want.data)),
			data:    want.data,
		})...)
	}
	return payload
}

func assertPrctlJSONPayloadSections(t *testing.T, got []jsonPayloadSection, want []wantPrctlJSONPayloadSection) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertPrctlJSONPayloadSection(t, got[i], want[i])
	}
}

func assertPrctlJSONPayloadSection(t *testing.T, got jsonPayloadSection, want wantPrctlJSONPayloadSection) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != 1 {
		t.Fatalf("prctl section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("prctl section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("prctl section lengths = %+v, want %+v", got, want)
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, want.data) {
		t.Fatalf("prctl section data = %v, want %v", data, want.data)
	}
}

func prctlJSONUint32(v uint32) []byte {
	data := make([]byte, prctlUint32PayloadSize)
	binary.LittleEndian.PutUint32(data, v)
	return data
}

func prctlJSONTLVKind(kind string) uint16 {
	if kind == "string" {
		return payloadTLVKindString
	}
	return payloadTLVKindStruct
}

func prctlJSONTLVFlags(direction string) uint16 {
	if direction == "out" {
		return payloadTLVFlagDirectionOut
	}
	return 0
}
