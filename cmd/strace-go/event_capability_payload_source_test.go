package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForPayloadEventUsesSourceAwareCapgetRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x2000},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	header := capabilityJSONBytes(1, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(2, capabilityDataPayloadSize)
	snapshot := make([]byte, payloadExitArgOffset+capabilityDataPayloadSize)
	copy(snapshot[payloadEnterArgOffset:], header)
	copy(snapshot[payloadExitArgOffset:], data)
	event := payloadEventFromRawForTest(raw, snapshot)

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "capget"})

	assertCapabilitySourceSections(t, sections, []wantCapabilitySourceSection{
		{argIndex: 0, direction: handler.PayloadDirectionIn, offset: payloadEnterArgOffset, userPtr: 0x1000, data: header},
		{argIndex: 1, direction: handler.PayloadDirectionOut, offset: payloadExitArgOffset, userPtr: 0x2000, data: data},
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareCapsetRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000},
		ProbeRetEnter: 0,
	}
	header := capabilityJSONBytes(3, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(4, capabilityDataPayloadSize)
	snapshot := make([]byte, payloadMiscArgOffset+capabilityDataPayloadSize)
	copy(snapshot[payloadEnterArgOffset:], header)
	copy(snapshot[payloadMiscArgOffset:], data)
	event := payloadEventFromRawForTest(raw, snapshot)

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "capset"})

	assertCapabilitySourceSections(t, sections, []wantCapabilitySourceSection{
		{argIndex: 0, direction: handler.PayloadDirectionIn, offset: payloadEnterArgOffset, userPtr: 0x1000, data: header},
		{argIndex: 1, direction: handler.PayloadDirectionIn, offset: payloadMiscArgOffset, userPtr: 0x2000, data: data},
	})
}

type wantCapabilitySourceSection struct {
	argIndex  int
	direction handler.PayloadDirection
	offset    int
	userPtr   uint64
	data      []byte
}

func assertCapabilitySourceSections(
	t *testing.T,
	got []handler.PayloadSection,
	want []wantCapabilitySourceSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertCapabilitySourceSection(t, got[i], want[i])
	}
}

func assertCapabilitySourceSection(
	t *testing.T,
	got handler.PayloadSection,
	want wantCapabilitySourceSection,
) {
	t.Helper()
	if got.Kind != handler.PayloadKindStruct || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("capability section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("capability section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("capability section lengths = %+v, want %d", got, len(want.data))
	}
	if string(got.Data) != string(want.data) {
		t.Fatalf("capability section data = %v, want %v", got.Data, want.data)
	}
}
