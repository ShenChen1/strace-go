package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareTimeRules(t *testing.T) {
	tests := []struct {
		name  string
		raw   bpfEvent
		wants []wantTimeJSONPayloadSection
	}{
		{
			name: "clock_settime",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0, 0x1000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 1, 0, 0x1000, 16, timeJSONStruct(1, 2)},
			},
		},
		{
			name: "gettimeofday",
			raw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{0x1000, 0x2000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "out", 0, 1024, 0x1000, 16, timeJSONStruct(3, 4)},
				{"struct", "out", 1, 1040, 0x2000, 8, timeJSONTimezone(5, 6)},
			},
		},
		{
			name: "settimeofday",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x3000, 0x4000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0, 0x3000, 16, timeJSONStruct(3, 4)},
				{"struct", "in", 1, 16, 0x4000, 8, timeJSONTimezone(5, 6)},
			},
		},
		{
			name: "nanosleep",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0x1000, 0x2000},
				Ret:           -4,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0, 0x1000, 16, timeJSONStruct(7, 8)},
				{"struct", "out", 1, 1024, 0x2000, 16, timeJSONStruct(9, 10)},
			},
		},
		{
			name: "adjtimex",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0, 0x3000, 208, timeJSONTimex(11)},
				{"struct", "out", 0, 1024, 0x3000, 208, timeJSONTimex(12)},
			},
		},
		{
			name: "setitimer",
			raw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0, 0x2000, 0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 1, 0, 0x2000, 32, timeJSONItimerval(5, 6, 7, 8)},
				{"struct", "out", 2, 1024, 0x3000, 32, timeJSONItimerval(9, 10, 11, 12)},
			},
		},
		{
			name: "utimensat",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{^uint64(99), 0x3000, 0x4000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"string", "in", 1, 0, 0x3000, 7, []byte("file-b\x00")},
				{"struct", "in", 2, 512, 0x4000, 32, timeJSONItimerval(3, 4, 5, 6)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := payloadEvent{
				raw: &tt.raw,
				source: staticPayloadSource{
					args: tt.raw.Args,
					data: timeSourcePayloadData(tt.wants),
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: tt.name})

			assertTimePayloadSections(t, sections, tt.wants)
		})
	}
}

func assertTimePayloadSections(
	t *testing.T,
	got []handler.PayloadSection,
	want []wantTimeJSONPayloadSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertTimePayloadSection(t, got[i], want[i])
	}
}

func assertTimePayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	want wantTimeJSONPayloadSection,
) {
	t.Helper()
	if string(got.Kind) != want.kind || string(got.Direction) != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr || got.UserLen != want.userLen {
		t.Fatalf("section bounds = %+v, want %+v", got, want)
	}
	if got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("section copied_len = %d, want %d", got.CopiedLen, len(want.data))
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("section data = %v, want %v", got.Data, want.data)
	}
}

func timeSourcePayloadData(wants []wantTimeJSONPayloadSection) []byte {
	size := 0
	for _, want := range wants {
		end := int(want.offset) + len(want.data)
		if end > size {
			size = end
		}
	}
	data := make([]byte, size)
	for _, want := range wants {
		copy(data[want.offset:], want.data)
	}
	return data
}
