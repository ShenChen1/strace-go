package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

const (
	capabilityHeaderPayloadSize = 8
	capabilityDataPayloadSize   = 24
)

func TestJSONSyscallEventIncludesCapgetPayloadSections(t *testing.T) {
	header := capabilityJSONBytes(1, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(2, capabilityDataPayloadSize)
	args := [6]uint64{0x1000, 0x2000}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: 0x1000,
			userLen: capabilityHeaderPayloadSize,
			data:    header,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: 0x2000,
			userLen: capabilityDataPayloadSize,
			data:    data,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "capget", bpfEventTypeExit, args, 0, payload)
	assertCapabilityJSONSections(t, ev.PayloadSections, []wantCapabilityJSONSection{
		{argIndex: 0, direction: "in", userPtr: 0x1000, data: header},
		{argIndex: 1, direction: "out", userPtr: 0x2000, data: data},
	})
}

func TestJSONSyscallEventIncludesCapsetPayloadSections(t *testing.T) {
	header := capabilityJSONBytes(3, capabilityHeaderPayloadSize)
	data := capabilityJSONBytes(4, capabilityDataPayloadSize)
	args := [6]uint64{0x1000, 0x2000}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: 0x1000,
			userLen: capabilityHeaderPayloadSize,
			data:    header,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: 0x2000,
			userLen: capabilityDataPayloadSize,
			data:    data,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "capset", bpfEventTypeEnter, args, 0, payload)
	assertCapabilityJSONSections(t, ev.PayloadSections, []wantCapabilityJSONSection{
		{argIndex: 0, direction: "in", userPtr: 0x1000, data: header},
		{argIndex: 1, direction: "in", userPtr: 0x2000, data: data},
	})
}

type wantCapabilityJSONSection struct {
	argIndex  int
	direction string
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

func TestSyscallEventContextMergesCapgetDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("capget")
	args := [6]uint64{0x1000, 0x2000}
	header := capabilityJSONBytes(1, capabilityHeaderPayloadSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     0,
		userPtr: args[0],
		userLen: capabilityHeaderPayloadSize,
		data:    header,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "capget", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	data := capabilityJSONBytes(2, capabilityDataPayloadSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: capabilityDataPayloadSize,
		data:    data,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "capget", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	assertCapabilityHandlerSection(t, ev.handlerContext, 0, handler.PayloadDirectionIn, header)
	assertCapabilityHandlerSection(t, ev.handlerContext, 1, handler.PayloadDirectionOut, data)
}

func TestSyscallEventContextKeepsCapsetDirectV1DataSize(t *testing.T) {
	session := miscStructTLVSession("capset")
	args := [6]uint64{0x1000, 0x2000}
	header := capabilityHeaderBytesForEventTest(0x19980330, 0)
	data := capabilityJSONBytes(4, capabilityDataPayloadSize/2)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     0,
		userPtr: args[0],
		userLen: capabilityHeaderPayloadSize,
		data:    header,
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(data)),
		data:    data,
	})...)
	enterEnvelope := testTLVSyscallEnvelope(t, "capset", bpfEventTypeEnter, args, 0, payload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "capset", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	assertCapabilityHandlerSection(t, ev.handlerContext, 0, handler.PayloadDirectionIn, header)
	assertCapabilityHandlerSection(t, ev.handlerContext, 1, handler.PayloadDirectionIn, data)
}

func assertCapabilityHandlerSection(
	t *testing.T,
	ctx *handler.Context,
	argIndex int,
	direction handler.PayloadDirection,
	want []byte,
) {
	t.Helper()
	section, ok := ctx.Section(argIndex, handler.PayloadKindStruct)
	if !ok || section.Direction != direction || string(section.Data) != string(want) {
		t.Fatalf("capability section arg %d = %+v, %v; want %s data %v", argIndex, section, ok, direction, want)
	}
}

func capabilityHeaderBytesForEventTest(version uint32, pid int32) []byte {
	data := make([]byte, capabilityHeaderPayloadSize)
	binary.LittleEndian.PutUint32(data[0:4], version)
	binary.LittleEndian.PutUint32(data[4:8], uint32(pid))
	return data
}
