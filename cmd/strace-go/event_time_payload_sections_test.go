package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type wantTimeJSONPayloadSection struct {
	kind      string
	direction string
	argIndex  int
	userPtr   uint64
	userLen   uint32
	data      []byte
}

func TestJSONSyscallEventIncludesClockTimePayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		want     wantTimeJSONPayloadSection
	}{
		{
			name: "clock_settime",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0, 0x1000},
				ProbeRetEnter: 0,
			},
			want: wantTimeJSONPayloadSection{"struct", "in", 1, 0x1000, 16, timeJSONStruct(1, 2)},
		},
		{
			name: "clock_gettime",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{0, 0x2000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			want: wantTimeJSONPayloadSection{"struct", "out", 1, 0x2000, 16, timeJSONStruct(1, 2)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putTimeJSONPayloads(t, &eventRaw, []wantTimeJSONPayloadSection{tt.want})
			ev := timeJSONSyscallEvent(&eventRaw, tt.name)
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertTimeJSONPayloadSection(t, ev.PayloadSections[0], tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesGetSettimeofdayPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantTimeJSONPayloadSection
	}{
		{
			name: "gettimeofday",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{0x1000, 0x2000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "out", 0, 0x1000, 16, timeJSONStruct(3, 4)},
				{"struct", "out", 1, 0x2000, 8, timeJSONTimezone(5, 6)},
			},
		},
		{
			name: "settimeofday",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x3000, 0x4000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0x3000, 16, timeJSONStruct(3, 4)},
				{"struct", "in", 1, 0x4000, 8, timeJSONTimezone(5, 6)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putTimeJSONPayloads(t, &eventRaw, tt.wants)
			ev := timeJSONSyscallEvent(&eventRaw, tt.name)
			assertTimeJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

func TestJSONSyscallEventIncludesSleepAndTimexPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantTimeJSONPayloadSection
	}{
		{
			name: "nanosleep",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0x1000, 0x2000},
				Ret:           -4,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0x1000, 16, timeJSONStruct(7, 8)},
				{"struct", "out", 1, 0x2000, 16, timeJSONStruct(9, 10)},
			},
		},
		{
			name: "adjtimex",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 0, 0x3000, 208, timeJSONTimex(11)},
				{"struct", "out", 0, 0x3000, 208, timeJSONTimex(12)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putTimeJSONPayloads(t, &eventRaw, tt.wants)
			ev := timeJSONSyscallEvent(&eventRaw, tt.name)
			assertTimeJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

func TestJSONSyscallEventIncludesItimerPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantTimeJSONPayloadSection
	}{
		{
			name: "getitimer",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{0, 0x1000},
				Ret:          0,
				ProbeRetExit: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "out", 1, 0x1000, 32, timeJSONItimerval(1, 2, 3, 4)},
			},
		},
		{
			name: "setitimer",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{0, 0x2000, 0x3000},
				Ret:           0,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"struct", "in", 1, 0x2000, 32, timeJSONItimerval(5, 6, 7, 8)},
				{"struct", "out", 2, 0x3000, 32, timeJSONItimerval(9, 10, 11, 12)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putTimeJSONPayloads(t, &eventRaw, tt.wants)
			ev := timeJSONSyscallEvent(&eventRaw, tt.name)
			assertTimeJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

func TestJSONSyscallEventIncludesFileTimePayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		wants    []wantTimeJSONPayloadSection
	}{
		{
			name: "utime",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x1000, 0x2000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"string", "in", 0, 0x1000, 7, []byte("file-a\x00")},
				{"struct", "in", 1, 0x2000, 16, timeJSONStruct(1, 2)},
			},
		},
		{
			name: "utimensat",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{^uint64(99), 0x3000, 0x4000},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"string", "in", 1, 0x3000, 7, []byte("file-b\x00")},
				{"struct", "in", 2, 0x4000, 32, timeJSONItimerval(3, 4, 5, 6)},
			},
		},
		{
			name: "utimes",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x5000, 0},
				ProbeRetEnter: 0,
			},
			wants: []wantTimeJSONPayloadSection{
				{"string", "in", 0, 0x5000, 8, []byte("no-time\x00")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			putTimeJSONPayloads(t, &eventRaw, tt.wants)
			ev := timeJSONSyscallEvent(&eventRaw, tt.name)
			assertTimeJSONPayloadSections(t, ev.PayloadSections, tt.wants)
		})
	}
}

func timeJSONSyscallEvent(eventRaw *bpfEvent, name string) jsonSyscallEvent {
	scMeta := meta.Syscall{Name: name}
	return newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
}

func putTimeJSONPayloads(t *testing.T, eventRaw *bpfEvent, wants []wantTimeJSONPayloadSection) {
	t.Helper()
	payload := timeJSONTLVPayload(t, wants)
	eventRaw.EventFlags |= bpfEventFlagPayloadTLV
	eventRaw.DataLen = uint32(len(payload))
	copy(eventRaw.StrArg[:], payload)
}

func timeJSONTLVPayload(t *testing.T, wants []wantTimeJSONPayloadSection) []byte {
	t.Helper()
	var payload []byte
	for _, want := range wants {
		payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    timeJSONTLVKind(t, want.kind),
			flags:   timeJSONTLVFlags(t, want.direction),
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: want.userLen,
			data:    want.data,
		})...)
	}
	return payload
}

func timeJSONTLVKind(t *testing.T, kind string) uint16 {
	t.Helper()
	switch handler.PayloadKind(kind) {
	case handler.PayloadKindString:
		return payloadTLVKindString
	case handler.PayloadKindStruct:
		return payloadTLVKindStruct
	default:
		t.Fatalf("unsupported time payload kind %q", kind)
		return 0
	}
}

func timeJSONTLVFlags(t *testing.T, direction string) uint16 {
	t.Helper()
	switch handler.PayloadDirection(direction) {
	case handler.PayloadDirectionIn:
		return 0
	case handler.PayloadDirectionOut:
		return payloadTLVFlagDirectionOut
	default:
		t.Fatalf("unsupported time payload direction %q", direction)
		return 0
	}
}

func assertTimeJSONPayloadSections(
	t *testing.T,
	got []jsonPayloadSection,
	want []wantTimeJSONPayloadSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertTimeJSONPayloadSection(t, got[i], want[i])
	}
}

func assertTimeJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantTimeJSONPayloadSection,
) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr || got.UserLen != want.userLen {
		t.Fatalf("section bounds = %+v, want %+v", got, want)
	}
	if got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("section copied_len = %d, want %d", got.CopiedLen, len(want.data))
	}
	gotData := mustDecodeBase64(t, got.DataBase64)
	if string(gotData) != string(want.data) {
		t.Fatalf("section data = %v, want %v", gotData, want.data)
	}
}

func timeJSONStruct(sec uint64, subsec uint64) []byte {
	data := make([]byte, timespecPayloadStructSize)
	binary.LittleEndian.PutUint64(data[0:8], sec)
	binary.LittleEndian.PutUint64(data[8:16], subsec)
	return data
}

func timeJSONTimezone(west uint32, dst uint32) []byte {
	data := make([]byte, timePayloadTimezoneSize)
	binary.LittleEndian.PutUint32(data[0:4], west)
	binary.LittleEndian.PutUint32(data[4:8], dst)
	return data
}

func timeJSONTimex(modes uint32) []byte {
	data := make([]byte, timePayloadTimexSize)
	binary.LittleEndian.PutUint32(data[0:4], modes)
	return data
}

func timeJSONItimerval(aSec uint64, aSub uint64, bSec uint64, bSub uint64) []byte {
	data := make([]byte, timePayloadItimervalSize)
	copy(data[0:16], timeJSONStruct(aSec, aSub))
	copy(data[16:32], timeJSONStruct(bSec, bSub))
	return data
}
