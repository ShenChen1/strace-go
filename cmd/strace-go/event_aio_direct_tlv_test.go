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

func TestSyscallEventContextMergesAioCancelDirectTLVSection(t *testing.T) {
	session := miscStructTLVSession("io_cancel")
	args := [6]uint64{0xabc, 0x2000, 0x3000}
	iocbData := aioTestIocbData(1, 0x4000, 3)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(iocbData)),
		data:    iocbData,
	})
	enterRaw := miscStructTLVEvent(t, "io_cancel", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "io_cancel", bpfEventTypeExit, args, -22, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, iocbData) {
		t.Fatalf("io_cancel iocb section = %+v, %v; want pending enter IN struct TLV", section, ok)
	}
}
