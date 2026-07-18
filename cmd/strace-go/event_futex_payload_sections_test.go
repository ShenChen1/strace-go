package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type wantFutexJSONPayloadSection struct {
	kind      string
	direction string
	argIndex  int
	offset    uint32
	userPtr   uint64
	userLen   uint32
	data      []byte
}

func TestJSONSyscallEventIncludesFutexPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
		want     wantFutexJSONPayloadSection
	}{
		{
			name: "futex",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x2000, 0, 7, 0x1000},
				DataLen:       timespecPayloadStructSize,
				ProbeRetEnter: 0,
			},
			want: wantFutexJSONPayloadSection{"struct", "in", 3, 0, 0x1000, 16, futexJSONTimespec(1, 2)},
		},
		{
			name: "futex_wait",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x2000, 7, 0xffffffff, 0, 0x3000},
				DataLen:       timespecPayloadStructSize,
				ProbeRetEnter: 0,
			},
			want: wantFutexJSONPayloadSection{"struct", "in", 4, 0, 0x3000, 16, futexJSONTimespec(3, 4)},
		},
		{
			name: "futex_requeue",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x4000},
				DataLen:       futexPayloadRequeueSize,
				ProbeRetEnter: 0,
			},
			want: wantFutexJSONPayloadSection{"struct", "in", 0, 0, 0x4000, 48, futexJSONWaitvPair()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			copy(eventRaw.StrArg[tt.want.offset:], tt.want.data)
			ev := futexJSONSyscallEvent(&eventRaw, tt.name)
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertFutexJSONPayloadSection(t, ev.PayloadSections[0], tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesFutexWaitvPayloadSections(t *testing.T) {
	waiters := futexJSONWaitvPair()
	timeout := futexJSONTimespec(9, 10)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 2, 0, 0x4000},
		DataLen:       futexPayloadWaitvTimeoutOffset + timespecPayloadStructSize,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], waiters)
	copy(eventRaw.StrArg[futexPayloadWaitvTimeoutOffset:], timeout)

	ev := futexJSONSyscallEvent(eventRaw, "futex_waitv")
	want := []wantFutexJSONPayloadSection{
		{"struct", "in", 0, 0, 0x1000, 48, waiters},
		{"struct", "in", 3, futexPayloadWaitvTimeoutOffset, 0x4000, 16, timeout},
	}
	if len(ev.PayloadSections) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), len(want))
	}
	for i := range want {
		assertFutexJSONPayloadSection(t, ev.PayloadSections[i], want[i])
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareFutexRules(t *testing.T) {
	tests := []struct {
		name    string
		raw     bpfEvent
		want    handler.PayloadSection
		payload []byte
	}{
		{
			name: "futex",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x2000, 0, 7, 0x1000},
				ProbeRetEnter: 0,
			},
			want: handler.PayloadSection{
				Kind:      handler.PayloadKindStruct,
				Direction: handler.PayloadDirectionIn,
				ArgIndex:  3,
				UserPtr:   0x1000,
				UserLen:   timespecPayloadStructSize,
			},
			payload: futexJSONTimespec(1, 2),
		},
		{
			name: "futex_wait",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x2000, 7, 0xffffffff, 0, 0x3000},
				ProbeRetEnter: 0,
			},
			want: handler.PayloadSection{
				Kind:      handler.PayloadKindStruct,
				Direction: handler.PayloadDirectionIn,
				ArgIndex:  4,
				UserPtr:   0x3000,
				UserLen:   timespecPayloadStructSize,
			},
			payload: futexJSONTimespec(3, 4),
		},
		{
			name: "futex_requeue",
			raw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{0x4000},
				ProbeRetEnter: 0,
			},
			want: handler.PayloadSection{
				Kind:      handler.PayloadKindStruct,
				Direction: handler.PayloadDirectionIn,
				ArgIndex:  0,
				UserPtr:   0x4000,
				UserLen:   futexPayloadRequeueSize,
			},
			payload: futexJSONWaitvPair(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := payloadEventFromRawForTest(&tt.raw, tt.payload)

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: tt.name})

			if len(sections) != 1 {
				t.Fatalf("sections = %d, want 1", len(sections))
			}
			assertFutexPayloadSection(t, sections[0], tt.want, tt.payload)
		})
	}
}

func TestFutexPayloadSectionsRecognizeTimeoutOps(t *testing.T) {
	tests := []struct {
		name string
		op   uint64
		want bool
	}{
		{name: "wait", op: 0, want: true},
		{name: "wait private", op: 128, want: true},
		{name: "wait bitset clock", op: 9 | 256, want: true},
		{name: "lock pi", op: 6, want: true},
		{name: "lock pi2 private", op: 13 | 128, want: true},
		{name: "wait requeue pi", op: 11, want: true},
		{name: "futex fd", op: 2, want: false},
		{name: "wake", op: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := futexHasTimeout(tt.op); got != tt.want {
				t.Fatalf("futexHasTimeout(%#x) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareFutexWaitvRule(t *testing.T) {
	waiters := futexJSONWaitvPair()
	timeout := futexJSONTimespec(9, 10)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 2, 0, 0x4000},
		ProbeRetEnter: 0,
	}
	data := make([]byte, futexPayloadWaitvTimeoutOffset+timespecPayloadStructSize)
	copy(data[:], waiters)
	copy(data[futexPayloadWaitvTimeoutOffset:], timeout)
	event := payloadEventFromRawForTest(raw, data)

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "futex_waitv"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	assertFutexPayloadSection(t, sections[0], handler.PayloadSection{
		Kind:      handler.PayloadKindStruct,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		UserPtr:   0x1000,
		UserLen:   uint32(len(waiters)),
	}, waiters)
	assertFutexPayloadSection(t, sections[1], handler.PayloadSection{
		Kind:      handler.PayloadKindStruct,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  3,
		UserPtr:   0x4000,
		UserLen:   timespecPayloadStructSize,
	}, timeout)
}

func futexJSONSyscallEvent(eventRaw *bpfEvent, name string) jsonSyscallEvent {
	scMeta := meta.Syscall{Name: name}
	return newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
}

func assertFutexJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantFutexJSONPayloadSection,
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

func assertFutexPayloadSection(
	t *testing.T,
	got handler.PayloadSection,
	want handler.PayloadSection,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != want.Kind || got.Direction != want.Direction || got.ArgIndex != want.ArgIndex {
		t.Fatalf("section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.UserPtr || got.UserLen != want.UserLen {
		t.Fatalf("section bounds = %+v, want %+v", got, want)
	}
	if got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("section copied_len = %d, want %d", got.CopiedLen, len(wantData))
	}
	if !bytes.Equal(got.Data, wantData) {
		t.Fatalf("section data = %v, want %v", got.Data, wantData)
	}
}

func futexJSONWaitvPair() []byte {
	return append(futexJSONWaitvData(1, 0x5000, 0), futexJSONWaitvData(2, 0x6000, 1)...)
}

func futexJSONWaitvData(val uint64, addr uint64, flags uint32) []byte {
	data := make([]byte, futexPayloadWaitvElemSize)
	binary.LittleEndian.PutUint64(data[0:8], val)
	binary.LittleEndian.PutUint64(data[8:16], addr)
	binary.LittleEndian.PutUint32(data[16:20], flags)
	return data
}

func futexJSONTimespec(sec uint64, nsec uint64) []byte {
	data := make([]byte, timespecPayloadStructSize)
	binary.LittleEndian.PutUint64(data[0:8], sec)
	binary.LittleEndian.PutUint64(data[8:16], nsec)
	return data
}
