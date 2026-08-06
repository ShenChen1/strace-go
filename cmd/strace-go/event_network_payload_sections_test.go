package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

const socklenPayloadSize = 4

func jsonSockaddrInet(port uint16, ip [4]byte) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.BigEndian.PutUint16(data[2:4], port)
	copy(data[4:8], ip[:])
	return data
}

type wantNetworkJSONPayloadSection struct {
	kind      string
	direction string
	argIndex  int
	userPtr   uint64
	userLen   uint32
	data      []byte
}

func TestJSONSyscallEventIncludesConnectSockaddrSection(t *testing.T) {
	sockaddr := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	want := []wantNetworkJSONPayloadSection{
		{
			kind:      string(handler.PayloadKindStruct),
			direction: string(handler.PayloadDirectionIn),
			argIndex:  1,
			userPtr:   0x4000,
			userLen:   16,
			data:      sockaddr,
		},
	}
	args := [6]uint64{3, 0x4000, 16}
	payload := payloadTLVBytesForTest(t, networkJSONTLVSections(t, want)...)

	ev := newJSONSyscallEventFromTLVForTest(t, "connect", bpfEventTypeEnter, args, 0, payload)
	assertNetworkJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesSendtoBufferAndSockaddrSections(t *testing.T) {
	sockaddr := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	want := []wantNetworkJSONPayloadSection{
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionIn),
			argIndex:  1,
			userPtr:   0x2000,
			userLen:   3,
			data:      []byte("abc"),
		},
		{
			kind:      string(handler.PayloadKindStruct),
			direction: string(handler.PayloadDirectionIn),
			argIndex:  4,
			userPtr:   0x4000,
			userLen:   16,
			data:      sockaddr,
		},
	}
	args := [6]uint64{3, 0x2000, 3, 0, 0x4000, 16}
	payload := payloadTLVBytesForTest(t, networkJSONTLVSections(t, want)...)

	ev := newJSONSyscallEventFromTLVForTest(t, "sendto", bpfEventTypeEnter, args, 0, payload)
	assertNetworkJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesRecvfromBufferSockaddrAndLenSections(t *testing.T) {
	sockaddr := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	inLen := networkJSONSocklen(16)
	outLen := networkJSONSocklen(16)
	want := []wantNetworkJSONPayloadSection{
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionIn),
			argIndex:  5,
			userPtr:   0x5000,
			userLen:   socklenPayloadSize,
			data:      inLen,
		},
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionOut),
			argIndex:  1,
			userPtr:   0x2000,
			userLen:   3,
			data:      []byte("abc"),
		},
		{
			kind:      string(handler.PayloadKindStruct),
			direction: string(handler.PayloadDirectionOut),
			argIndex:  4,
			userPtr:   0x4000,
			userLen:   16,
			data:      sockaddr,
		},
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionOut),
			argIndex:  5,
			userPtr:   0x5000,
			userLen:   socklenPayloadSize,
			data:      outLen,
		},
	}
	args := [6]uint64{3, 0x2000, 5, 0, 0x4000, 0x5000}
	payload := payloadTLVBytesForTest(t, networkJSONTLVSections(t, want)...)

	ev := newJSONSyscallEventFromTLVForTest(t, "recvfrom", bpfEventTypeExit, args, 3, payload)
	assertNetworkJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesAcceptSockaddrAndLenSections(t *testing.T) {
	sockaddr := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	inLen := networkJSONSocklen(16)
	outLen := networkJSONSocklen(16)
	want := []wantNetworkJSONPayloadSection{
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionIn),
			argIndex:  2,
			userPtr:   0x5000,
			userLen:   socklenPayloadSize,
			data:      inLen,
		},
		{
			kind:      string(handler.PayloadKindStruct),
			direction: string(handler.PayloadDirectionOut),
			argIndex:  1,
			userPtr:   0x4000,
			userLen:   16,
			data:      sockaddr,
		},
		{
			kind:      string(handler.PayloadKindBytes),
			direction: string(handler.PayloadDirectionOut),
			argIndex:  2,
			userPtr:   0x5000,
			userLen:   socklenPayloadSize,
			data:      outLen,
		},
	}
	args := [6]uint64{3, 0x4000, 0x5000}
	payload := payloadTLVBytesForTest(t, networkJSONTLVSections(t, want)...)

	ev := newJSONSyscallEventFromTLVForTest(t, "accept", bpfEventTypeExit, args, 4, payload)
	assertNetworkJSONPayloadSections(t, ev.PayloadSections, want)
}

func networkJSONTLVSections(t *testing.T, wants []wantNetworkJSONPayloadSection) []payloadTLVTestSection {
	t.Helper()
	sections := make([]payloadTLVTestSection, 0, len(wants))
	for _, want := range wants {
		sections = append(sections, payloadTLVTestSection{
			kind:    networkJSONTLVKind(t, want.kind),
			flags:   networkJSONTLVFlags(t, want.direction),
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: want.userLen,
			data:    want.data,
		})
	}
	return sections
}

func networkJSONTLVKind(t *testing.T, kind string) uint16 {
	t.Helper()
	switch handler.PayloadKind(kind) {
	case handler.PayloadKindBytes:
		return payloadTLVKindBytes
	case handler.PayloadKindStruct:
		return payloadTLVKindStruct
	default:
		t.Fatalf("unsupported network payload kind %q", kind)
		return 0
	}
}

func networkJSONTLVFlags(t *testing.T, direction string) uint16 {
	t.Helper()
	switch handler.PayloadDirection(direction) {
	case handler.PayloadDirectionIn:
		return 0
	case handler.PayloadDirectionOut:
		return payloadTLVFlagDirectionOut
	default:
		t.Fatalf("unsupported network payload direction %q", direction)
		return 0
	}
}

func networkJSONSocklen(value uint32) []byte {
	data := make([]byte, socklenPayloadSize)
	binary.LittleEndian.PutUint32(data, value)
	return data
}

func assertNetworkJSONPayloadSections(
	t *testing.T,
	got []jsonPayloadSection,
	want []wantNetworkJSONPayloadSection,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertNetworkJSONPayloadSection(t, got[i], want[i])
	}
}

func assertNetworkJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantNetworkJSONPayloadSection,
) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("network section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr || got.UserLen != want.userLen || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("network section bounds = %+v, want %+v", got, want)
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != string(want.data) {
		t.Fatalf("network section data = %v, want %v", data, want.data)
	}
}
