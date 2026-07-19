package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesAioSetupDirectTLVSection(t *testing.T) {
	session := miscStructTLVSession("io_setup")
	args := [6]uint64{128, 0x1000}
	ctxData := aioTestPointerBytes(0xabc)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(ctxData)),
		data:    ctxData,
	})
	exitRaw := miscStructTLVEvent(t, "io_setup", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionOut || !bytes.Equal(section.Data, ctxData) {
		t.Fatalf("io_setup ctx section = %+v, %v; want direct OUT struct TLV", section, ok)
	}
}
