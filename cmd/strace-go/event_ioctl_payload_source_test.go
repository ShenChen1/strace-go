package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type expectedIoctlSection struct {
	index     int
	direction handler.PayloadDirection
	offset    uint32
	userLen   uint32
	data      []byte
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareIoctlEnterRule(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, ioctlTestCmdSize(len(wantData)), 0x1000},
		ProbeRetEnter: 0,
	}
	sections := ioctlSourceSections(raw, ioctlSourcePayload(ioctlArgPayloadOffset, wantData))

	requireIoctlSection(t, sections, expectedIoctlSection{
		index: 0, direction: handler.PayloadDirectionIn,
		offset: ioctlArgPayloadOffset, userLen: uint32(len(wantData)), data: wantData,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareIoctlExitRule(t *testing.T) {
	inData := bytes.Repeat([]byte{0x11}, 8)
	outData := bytes.Repeat([]byte{0x22}, 8)
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, ioctlTestCmdSize(len(inData)), 0x1000},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	sections := ioctlSourceSections(raw, ioctlExitSourcePayload(inData, outData))
	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	requireIoctlSection(t, sections, expectedIoctlSection{
		index: 0, direction: handler.PayloadDirectionIn,
		offset: ioctlArgPayloadOffset, userLen: uint32(len(inData)), data: inData,
	})
	requireIoctlSection(t, sections, expectedIoctlSection{
		index: 1, direction: handler.PayloadDirectionOut,
		offset: payloadExitArgOffset, userLen: uint32(len(outData)), data: outData,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareIoctlZeroSizeRule(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x7f}, ioctlArgZeroPayloadLen)
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0, 0x1000},
		ProbeRetEnter: 0,
	}
	sections := ioctlSourceSections(raw, ioctlSourcePayload(ioctlArgPayloadOffset, wantData))

	requireIoctlSection(t, sections, expectedIoctlSection{
		index: 0, direction: handler.PayloadDirectionIn,
		offset: ioctlArgPayloadOffset, userLen: ioctlArgZeroPayloadLen, data: wantData,
	})
}

func ioctlSourceSections(raw *bpfEvent, data []byte) []handler.PayloadSection {
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}
	return payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "ioctl"})
}

func ioctlSourcePayload(offset int, data []byte) []byte {
	payload := make([]byte, offset+len(data))
	copy(payload[offset:], data)
	return payload
}

func ioctlExitSourcePayload(inData []byte, outData []byte) []byte {
	dataLen := ioctlArgPayloadOffset + len(inData)
	if minLen := payloadExitArgOffset + len(outData); dataLen < minLen {
		dataLen = minLen
	}
	payload := make([]byte, dataLen)
	copy(payload[ioctlArgPayloadOffset:], inData)
	copy(payload[payloadExitArgOffset:], outData)
	return payload
}

func requireIoctlSection(t *testing.T, sections []handler.PayloadSection, want expectedIoctlSection) {
	t.Helper()
	if want.index >= len(sections) {
		t.Fatalf("missing section %d in %d sections", want.index, len(sections))
	}
	got := sections[want.index]
	if got.Kind != handler.PayloadKindBytes || got.Direction != want.direction || got.ArgIndex != 2 {
		t.Fatalf("ioctl section %d metadata = %+v", want.index, got)
	}
	if got.Offset != want.offset || got.UserPtr != 0x1000 || got.UserLen != want.userLen {
		t.Fatalf("ioctl section %d bounds = %+v", want.index, got)
	}
	if got.CopiedLen != uint32(len(want.data)) || !bytes.Equal(got.Data, want.data) {
		t.Fatalf("ioctl section %d data = %v, want %v", want.index, got.Data, want.data)
	}
}
