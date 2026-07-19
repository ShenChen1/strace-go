package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesPathOnlyTLVSection(t *testing.T) {
	session := miscStructTLVSession("mkdir")
	args := [6]uint64{0x2000}
	pathData := []byte("/tmp/path-direct\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(pathData)),
		data:    pathData,
	})
	enterRaw := miscStructTLVEvent(t, "mkdir", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "mkdir", bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	section, ok := ev.handlerContext.Section(0, handler.PayloadKindString)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, pathData) {
		t.Fatalf("mkdir path section = %+v, %v; want pending enter string TLV", section, ok)
	}
}
