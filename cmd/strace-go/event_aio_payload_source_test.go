package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type expectedAioSection struct {
	index     int
	kind      handler.PayloadKind
	direction handler.PayloadDirection
	argIndex  int
	offset    uint32
	userPtr   uint64
	data      []byte
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAioSetupRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{128, 0x1000},
		Ret:          0,
		ProbeRetExit: 0,
	}
	data := make([]byte, payloadExitArgOffset+aioPayloadPointerSize)
	copy(data[payloadExitArgOffset:], aioTestPointerBytes(0xabc))

	sections := aioSourceSections(raw, "io_setup", data)
	requireAioSection(t, sections, expectedAioSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionOut,
		argIndex: 1, offset: payloadExitArgOffset, userPtr: 0x1000,
		data: aioTestPointerBytes(0xabc),
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAioSubmitRule(t *testing.T) {
	iocb0 := aioTestIocbData(1, 0x4000, 3)
	iocb1 := aioTestIocbData(0, 0x5000, 4)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0xabc, 2, 0x1000},
		ProbeRetEnter: 0,
	}
	sections := aioSourceSections(raw, "io_submit", aioSubmitSourcePayload(iocb0, iocb1))
	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(sections))
	}
	requireAioSection(t, sections, expectedAioSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 2, offset: payloadEnterArgOffset, userPtr: 0x1000,
		data: append(aioTestPointerBytes(0x2000), aioTestPointerBytes(0x3000)...),
	})
	requireAioSection(t, sections, expectedAioSection{
		index: 1, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: handler.AioSubmitIocbPayloadArgBase, offset: payloadMiscArgOffset,
		userPtr: 0x2000, data: iocb0,
	})
	requireAioSection(t, sections, expectedAioSection{
		index: 2, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: handler.AioSubmitIocbPayloadArgBase + 1,
		offset:   payloadMiscArgOffset + aioPayloadIocbSize,
		userPtr:  0x3000, data: iocb1,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAioCancelRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0xabc, 0x2000, 0},
		ProbeRetEnter: 0,
	}
	iocb := aioTestIocbData(1, 0x4000, 3)
	data := make([]byte, payloadEnterArgOffset+aioPayloadIocbSize)
	copy(data[payloadEnterArgOffset:], iocb)

	sections := aioSourceSections(raw, "io_cancel", data)
	requireAioSection(t, sections, expectedAioSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 1, offset: payloadEnterArgOffset, userPtr: 0x2000, data: iocb,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAioGeteventsRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{0xabc, 0, 1, 0x7000},
		Ret:          1,
		ProbeRetExit: 0,
	}
	events := aioTestIoEventData(0x11, 0x22, 3, 4)
	data := make([]byte, payloadExitArgOffset+aioPayloadEventsElemSize)
	copy(data[payloadExitArgOffset:], events)

	sections := aioSourceSections(raw, "io_getevents", data)
	requireAioSection(t, sections, expectedAioSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionOut,
		argIndex: 3, offset: payloadExitArgOffset, userPtr: 0x7000, data: events,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAioPgeteventsRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0xabc, 0, 0, 0, 0x4000, 0x5000},
		ProbeRetEnter: 0,
	}
	timeout := aioTestTimespecData(5, 6)
	sigset := append(aioTestPointerBytes(0x6000), aioTestPointerBytes(8)...)
	mask := aioTestPointerBytes(1)

	sections := aioSourceSections(raw, "io_pgetevents", aioPgeteventsSourcePayload(timeout, sigset, mask))
	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(sections))
	}
	requireAioSection(t, sections, expectedAioSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 4, offset: payloadMiscArgOffset, userPtr: 0x4000, data: timeout,
	})
	requireAioSection(t, sections, expectedAioSection{
		index: 1, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 5, offset: aioPayloadSigsetOffset, userPtr: 0x5000, data: sigset,
	})
	requireAioSection(t, sections, expectedAioSection{
		index: 2, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionIn,
		argIndex: 5, offset: aioPayloadSigmaskOffset, userPtr: 0x6000, data: mask,
	})
}

func aioSourceSections(raw *bpfEvent, syscall string, data []byte) []handler.PayloadSection {
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}
	return payloadSectionsForPayloadEvent(event, meta.Syscall{Name: syscall})
}

func aioSubmitSourcePayload(iocb0 []byte, iocb1 []byte) []byte {
	data := make([]byte, payloadMiscArgOffset+2*aioPayloadIocbSize)
	copy(data[payloadEnterArgOffset:], append(aioTestPointerBytes(0x2000), aioTestPointerBytes(0x3000)...))
	copy(data[payloadMiscArgOffset:], iocb0)
	copy(data[payloadMiscArgOffset+aioPayloadIocbSize:], iocb1)
	return data
}

func aioPgeteventsSourcePayload(timeout []byte, sigset []byte, mask []byte) []byte {
	data := make([]byte, aioPayloadSigmaskOffset+len(mask))
	copy(data[payloadMiscArgOffset:], timeout)
	copy(data[aioPayloadSigsetOffset:], sigset)
	copy(data[aioPayloadSigmaskOffset:], mask)
	return data
}

func requireAioSection(t *testing.T, sections []handler.PayloadSection, want expectedAioSection) {
	t.Helper()
	if want.index >= len(sections) {
		t.Fatalf("missing section %d in %d sections", want.index, len(sections))
	}
	got := sections[want.index]
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("section %d metadata = %+v, want %s/%s arg %d",
			want.index, got, want.kind, want.direction, want.argIndex)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr {
		t.Fatalf("section %d bounds = %+v, want offset %d ptr %#x",
			want.index, got, want.offset, want.userPtr)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("section %d lengths = %+v, want %d", want.index, got, len(want.data))
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("section %d data = %v, want %v", want.index, got.Data, want.data)
	}
}
