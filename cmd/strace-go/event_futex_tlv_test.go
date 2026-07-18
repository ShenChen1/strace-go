package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesFutexTLVSection(t *testing.T) {
	session := miscStructTLVSession("futex")
	args := [6]uint64{0x1000, 0, 0, 0x2000}
	timeout := bytes.Repeat([]byte{0x44}, timespecPayloadStructSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     3,
		userPtr: args[3],
		userLen: timespecPayloadStructSize,
		data:    timeout,
	})
	enterRaw := miscStructTLVEvent(t, "futex", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "futex", bpfEventTypeExit, args, -110, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	section, ok := ev.handlerContext.PayloadStruct(3, handler.PayloadDirectionIn)
	if !ok || !bytes.Equal(section, timeout) {
		t.Fatalf("futex IN timeout section = %x, %v; want pending enter TLV struct", section, ok)
	}
}
