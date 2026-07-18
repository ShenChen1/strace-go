package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesTimexTLVSections(t *testing.T) {
	t.Run("adjtimex exit out timex", func(t *testing.T) {
		args := [6]uint64{0x4000}
		assertTimexExitTLVSection(t, "adjtimex", args, 0)
	})

	t.Run("clock_adjtime exit out timex", func(t *testing.T) {
		args := [6]uint64{0, 0x5000}
		assertTimexExitTLVSection(t, "clock_adjtime", args, 1)
	})
}

func assertTimexExitTLVSection(t *testing.T, syscallName string, args [6]uint64, argIndex uint16) {
	t.Helper()
	session := miscStructTLVSession(syscallName)
	enterRaw := miscStructTLVEvent(t, syscallName, bpfEventTypeEnter, args, 0, nil)
	enterRaw.EventFlags = bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	timexData := bytes.Repeat([]byte{0x2a}, timePayloadTimexSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     argIndex,
		userPtr: args[argIndex],
		userLen: timePayloadTimexSize,
		data:    timexData,
	})
	exitRaw := miscStructTLVEvent(t, syscallName, bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	section, ok := ev.handlerContext.PayloadStruct(int(argIndex), handler.PayloadDirectionOut)
	if !ok || !bytes.Equal(section, timexData) {
		t.Fatalf("%s OUT timex section = %x, %v; want exit TLV struct", syscallName, section, ok)
	}
}
