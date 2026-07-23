package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesFcntlDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("fcntl")
	args := [6]uint64{3, 5, 0x1000}
	enterData := bytes.Repeat([]byte{0x11}, fcntlFlockPayloadSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     2,
		userPtr: args[2],
		userLen: fcntlFlockPayloadSize,
		data:    enterData,
	})
	enterRaw := miscStructTLVEvent(t, "fcntl", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitData := bytes.Repeat([]byte{0x22}, fcntlFlockPayloadSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     2,
		userPtr: args[2],
		userLen: fcntlFlockPayloadSize,
		data:    exitData,
	})
	exitRaw := miscStructTLVEvent(t, "fcntl", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	requireFcntlDirectSection(t, ev, handler.PayloadDirectionIn, enterData)
	requireFcntlDirectSection(t, ev, handler.PayloadDirectionOut, exitData)
}

func requireFcntlDirectSection(
	t *testing.T,
	ev syscallEventContext,
	direction handler.PayloadDirection,
	want []byte,
) {
	t.Helper()
	section, ok := ev.handlerContext.PayloadStruct(2, direction)
	if !ok || !bytes.Equal(section, want) {
		t.Fatalf("fcntl %s section = %v, %v; want direct TLV struct", direction, section, ok)
	}
}
