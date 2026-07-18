package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesItimerTLVSections(t *testing.T) {
	t.Run("getitimer exit old value", func(t *testing.T) {
		args := [6]uint64{0, 0x1000}
		session := miscStructTLVSession("getitimer")
		outData := bytes.Repeat([]byte{0x36}, timePayloadItimervalSize)
		exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: args[1],
			userLen: timePayloadItimervalSize,
			data:    outData,
		})
		exitRaw := miscStructTLVEvent(t, "getitimer", bpfEventTypeExit, args, 0, exitPayload)
		exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

		section, ok := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionOut)
		if !ok || !bytes.Equal(section, outData) {
			t.Fatalf("getitimer OUT section = %x, %v; want exit TLV struct", section, ok)
		}
	})

	t.Run("setitimer new and old values", func(t *testing.T) {
		args := [6]uint64{0, 0x2000, 0x3000}
		session := miscStructTLVSession("setitimer")
		inData := bytes.Repeat([]byte{0x38}, timePayloadItimervalSize)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: timePayloadItimervalSize,
			data:    inData,
		})
		enterRaw := miscStructTLVEvent(t, "setitimer", bpfEventTypeEnter, args, 0, enterPayload)
		enterRaw.EventFlags |= bpfEventFlagGenericEnter
		session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

		outData := bytes.Repeat([]byte{0x39}, timePayloadItimervalSize)
		exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     2,
			userPtr: args[2],
			userLen: timePayloadItimervalSize,
			data:    outData,
		})
		exitRaw := miscStructTLVEvent(t, "setitimer", bpfEventTypeExit, args, 0, exitPayload)
		exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

		inSection, inOK := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		outSection, outOK := ev.handlerContext.PayloadStruct(2, handler.PayloadDirectionOut)
		if !inOK || !bytes.Equal(inSection, inData) {
			t.Fatalf("setitimer IN section = %x, %v; want pending enter TLV struct", inSection, inOK)
		}
		if !outOK || !bytes.Equal(outSection, outData) {
			t.Fatalf("setitimer OUT section = %x, %v; want exit TLV struct", outSection, outOK)
		}
	})
}
