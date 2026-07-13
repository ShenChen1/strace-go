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
				DataLen:       uint32(len("worker\x00")),
				ProbeRetEnter: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"string", "in", 0, 0x1000, []byte("worker\x00")},
			},
		},
		{
			name: "PR_GET_NAME",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{16, 0x2000},
				Ret:          0,
				DataLen:      payloadExitArgOffset + prctlNamePayloadSize,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"string", "out", payloadExitArgOffset, 0x2000, []byte("worker\x00")},
			},
		},
		{
			name: "PR_GET_CHILD_SUBREAPER",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{37, 0x3000},
				Ret:          0,
				DataLen:      payloadExitArgOffset + prctlUint32PayloadSize,
				ProbeRetExit: 0,
			},
			wants: []wantPrctlJSONPayloadSection{
				{"struct", "out", payloadExitArgOffset, 0x3000, prctlJSONUint32(1)},
			},
		},
		{
			name: "PR_SET_PDEATHSIG has no pointer payload",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{2, 15},
				DataLen:       prctlNamePayloadSize,
				ProbeRetEnter: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putPrctlJSONPayloads(&eventRaw, tt.wants)
			scMeta := meta.Syscall{Name: "prctl"}
			ev := newJSONSyscallEvent(&eventRaw, scMeta, payloadSectionsForEvent(&eventRaw, scMeta))
			assertPrctlJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

type wantPrctlJSONPayloadSection struct {
	kind      string
	direction string
	offset    int
	userPtr   uint64
	data      []byte
}

func putPrctlJSONPayloads(eventRaw *bpfEvent, wants []wantPrctlJSONPayloadSection) {
	for _, want := range wants {
		copy(eventRaw.StrArg[want.offset:], want.data)
	}
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
	if got.Offset != uint32(want.offset) || got.UserPtr != want.userPtr {
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
