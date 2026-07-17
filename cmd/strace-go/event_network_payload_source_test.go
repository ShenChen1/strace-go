package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type expectedNetworkSection struct {
	index     int
	kind      handler.PayloadKind
	direction handler.PayloadDirection
	argIndex  int
	userPtr   uint64
	userLen   uint32
}

func putSourceSocklen(data []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(data[offset:offset+socklenPayloadSize], value)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareConnectRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x4000, 16},
		ProbeRetEnter: 0,
	}
	sections := networkSourceSections(raw, "connect", jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 0, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 1, userPtr: 0x4000, userLen: 16,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareSendtoRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x2000, 3, 0, 0x4000, 16},
		ProbeRetEnter: 0,
	}
	sections := networkSourceSections(raw, "sendto", sendtoSourcePayload())
	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 0, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionIn,
		argIndex: 1, userPtr: 0x2000, userLen: 3,
	})
	if !bytes.Equal(sections[0].Data, []byte("abc")) {
		t.Fatalf("sendto buffer = %q, want abc", sections[0].Data)
	}
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 1, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionIn,
		argIndex: 4, userPtr: 0x4000, userLen: 16,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareRecvfromRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000, 5, 0, 0x4000, 0x5000},
		Ret:           3,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	sections := networkSourceSections(raw, "recvfrom", recvfromSourcePayload())
	if len(sections) != 4 {
		t.Fatalf("sections = %d, want 4", len(sections))
	}
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 0, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionIn,
		argIndex: 5, userPtr: 0x5000, userLen: socklenPayloadSize,
	})
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 1, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionOut,
		argIndex: 1, userPtr: 0x2000, userLen: 3,
	})
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 2, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionOut,
		argIndex: 4, userPtr: 0x4000, userLen: 16,
	})
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 3, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionOut,
		argIndex: 5, userPtr: 0x5000, userLen: socklenPayloadSize,
	})
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareAcceptRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x4000, 0x5000},
		Ret:           4,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	sections := networkSourceSections(raw, "accept", acceptSourcePayload())
	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(sections))
	}
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 0, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionIn,
		argIndex: 2, userPtr: 0x5000, userLen: socklenPayloadSize,
	})
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 1, kind: handler.PayloadKindStruct, direction: handler.PayloadDirectionOut,
		argIndex: 1, userPtr: 0x4000, userLen: 16,
	})
	requireNetworkSection(t, sections, expectedNetworkSection{
		index: 2, kind: handler.PayloadKindBytes, direction: handler.PayloadDirectionOut,
		argIndex: 2, userPtr: 0x5000, userLen: socklenPayloadSize,
	})
}

func networkSourceSections(raw *bpfEvent, syscall string, data []byte) []handler.PayloadSection {
	return payloadSectionsForPayloadEvent(networkSourceEvent(raw, data), meta.Syscall{Name: syscall})
}

func networkSourceEvent(raw *bpfEvent, data []byte) payloadEvent {
	return payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}
}

func sendtoSourcePayload() []byte {
	data := make([]byte, payloadMiscArgOffset+16)
	copy(data[:], []byte("abc"))
	copy(data[payloadMiscArgOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))
	return data
}

func recvfromSourcePayload() []byte {
	data := make([]byte, recvfromSockaddrOffset+16)
	putSourceSocklen(data, sockaddrLenEnterOffset, 16)
	copy(data[payloadExitArgOffset:], []byte("abc"))
	putSourceSocklen(data, sockaddrLenExitOffset, 16)
	copy(data[recvfromSockaddrOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))
	return data
}

func acceptSourcePayload() []byte {
	dataLen := acceptSockaddrOutOffset + 16
	if minLen := sockaddrLenExitOffset + socklenPayloadSize; dataLen < minLen {
		dataLen = minLen
	}
	data := make([]byte, dataLen)
	putSourceSocklen(data, sockaddrLenEnterOffset, 16)
	putSourceSocklen(data, sockaddrLenExitOffset, 16)
	copy(data[payloadExitArgOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))
	return data
}

func requireNetworkSection(
	t *testing.T,
	sections []handler.PayloadSection,
	want expectedNetworkSection,
) {
	t.Helper()
	if want.index >= len(sections) {
		t.Fatalf("missing section %d in %d sections", want.index, len(sections))
	}
	got := sections[want.index]
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex ||
		got.UserPtr != want.userPtr || got.UserLen != want.userLen {
		t.Fatalf("section %d = %+v, want %s/%s arg %d ptr %#x len %d",
			want.index, got, want.kind, want.direction, want.argIndex, want.userPtr, want.userLen)
	}
}
