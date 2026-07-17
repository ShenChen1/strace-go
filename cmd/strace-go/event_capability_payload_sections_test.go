package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesCapgetPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x2000},
		Ret:           0,
		DataLen:       payloadExitArgOffset + capabilityDataPayloadSize,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	header := capabilityJSONBytes(1, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(2, capabilityDataPayloadSize)
	copy(eventRaw.StrArg[:], header)
	copy(eventRaw.StrArg[payloadExitArgOffset:], data)

	scMeta := meta.Syscall{Name: "capget"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	assertCapabilityJSONSections(t, ev.PayloadSections, []wantCapabilityJSONSection{
		{argIndex: 0, direction: "in", offset: 0, userPtr: 0x1000, data: header},
		{argIndex: 1, direction: "out", offset: payloadExitArgOffset, userPtr: 0x2000, data: data},
	})
}

func TestJSONSyscallEventIncludesCapsetPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000},
		DataLen:       payloadMiscArgOffset + capabilityDataPayloadSize,
		ProbeRetEnter: 0,
	}
	header := capabilityJSONBytes(3, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(4, capabilityDataPayloadSize)
	copy(eventRaw.StrArg[:], header)
	copy(eventRaw.StrArg[payloadMiscArgOffset:], data)

	scMeta := meta.Syscall{Name: "capset"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	assertCapabilityJSONSections(t, ev.PayloadSections, []wantCapabilityJSONSection{
		{argIndex: 0, direction: "in", offset: 0, userPtr: 0x1000, data: header},
		{argIndex: 1, direction: "in", offset: payloadMiscArgOffset, userPtr: 0x2000, data: data},
	})
}

type wantCapabilityJSONSection struct {
	argIndex  int
	direction string
	offset    uint32
	userPtr   uint64
	data      []byte
}

func assertCapabilityJSONSections(
	t *testing.T,
	got []jsonPayloadSection,
	want []wantCapabilityJSONSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertCapabilityJSONSection(t, got[i], want[i])
	}
}

func assertCapabilityJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantCapabilityJSONSection,
) {
	t.Helper()
	if got.Kind != "struct" || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("capability section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("capability section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("capability section lengths = %+v, want %d", got, len(want.data))
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != string(want.data) {
		t.Fatalf("capability section data = %v, want %v", data, want.data)
	}
}

func capabilityJSONBytes(start byte, size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = start + byte(i)
	}
	return data
}
