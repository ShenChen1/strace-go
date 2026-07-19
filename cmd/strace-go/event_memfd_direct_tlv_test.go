package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesMemfdNameTLVSection(t *testing.T) {
	session := miscStructTLVSession("memfd_create")
	args := [6]uint64{0x2000, 0}
	nameData := []byte("memfd-direct\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(nameData)),
		data:    nameData,
	})
	enterRaw := miscStructTLVEvent(t, "memfd_create", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "memfd_create", bpfEventTypeExit, args, 3, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(0, handler.PayloadKindString)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, nameData) {
		t.Fatalf("memfd_create name section = %+v, %v; want pending enter string TLV", section, ok)
	}
}
