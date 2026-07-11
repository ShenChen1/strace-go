package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestSectionPayloadSourceServesWindowsByOffset(t *testing.T) {
	source := newSectionPayloadSource(
		[6]uint64{0x1000, 0x2000},
		[]payloadSourceWindow{
			{offset: 0, data: []byte("enter-payload")},
			{offset: handler.BpfMiscArgOffset, data: []byte("misc-payload")},
		},
	)

	arg, ok := source.Arg(1)
	if !ok || arg != 0x2000 {
		t.Fatalf("Arg(1) = %#x, %v; want 0x2000, true", arg, ok)
	}
	data, ok := source.PayloadWindow(handler.BpfMiscArgOffset+5, 4)
	if !ok || !bytes.Equal(data, []byte("payl")) {
		t.Fatalf("PayloadWindow = %q, %v; want payl, true", data, ok)
	}
}

func TestSectionPayloadSourceDoesNotStitchAdjacentWindows(t *testing.T) {
	source := newSectionPayloadSource(
		[6]uint64{},
		[]payloadSourceWindow{
			{offset: 0, data: []byte("abc")},
			{offset: 3, data: []byte("def")},
		},
	)

	data, ok := source.PayloadWindow(1, 5)
	if !ok || !bytes.Equal(data, []byte("bc")) {
		t.Fatalf("PayloadWindow = %q, %v; want first section suffix only", data, ok)
	}
}

func TestSectionPayloadSourceSkipsInvalidWindows(t *testing.T) {
	source := newSectionPayloadSource(
		[6]uint64{},
		[]payloadSourceWindow{
			{offset: -1, data: []byte("invalid")},
			{offset: 4, data: nil},
			{offset: 8, data: []byte("valid")},
		},
	)

	if _, ok := source.PayloadWindow(0, 8); ok {
		t.Fatal("PayloadWindow for invalid window = true, want false")
	}
	data, ok := source.PayloadWindow(8, 8)
	if !ok || !bytes.Equal(data, []byte("valid")) {
		t.Fatalf("PayloadWindow valid = %q, %v; want valid, true", data, ok)
	}
}

func TestPayloadSectionsForPayloadEventUsesSectionPayloadSource(t *testing.T) {
	event := payloadEvent{
		meta: payloadEventMeta{
			valid:        true,
			eventType:    bpfEventTypeExit,
			ret:          6,
			probeRetExit: 0,
		},
		source: newSectionPayloadSource(
			[6]uint64{3, 0x8000, 32},
			[]payloadSourceWindow{
				{offset: handler.BpfExitArgOffset, data: []byte("target")},
			},
		),
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "read"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindBytes || section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != 1 || section.UserPtr != 0x8000 || section.CopiedLen != 6 {
		t.Fatalf("read section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, []byte("target")) {
		t.Fatalf("read data = %q, want target", section.Data)
	}
}
