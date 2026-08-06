package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesTimeSetterTLVSections(t *testing.T) {
	t.Run("clock_settime timespec", func(t *testing.T) {
		args := [6]uint64{0, 0x1000}
		session := miscStructTLVSession("clock_settime")
		inData := bytes.Repeat([]byte{0x27}, timespecPayloadStructSize)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: timespecPayloadStructSize,
			data:    inData,
		})
		enterEnvelope := testTLVSyscallEnvelope(t, "clock_settime", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitEnvelope := testTLVSyscallEnvelope(t, "clock_settime", bpfEventTypeExit, args, -22, nil)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		section, ok := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		if !ok || !bytes.Equal(section, inData) {
			t.Fatalf("clock_settime IN section = %x, %v; want pending enter TLV struct", section, ok)
		}
	})

	t.Run("settimeofday timeval and timezone", func(t *testing.T) {
		args := [6]uint64{0x2000, 0x3000}
		session := miscStructTLVSession("settimeofday")
		tvData := bytes.Repeat([]byte{0x16}, timespecPayloadStructSize)
		tzData := bytes.Repeat([]byte{0x08}, timePayloadTimezoneSize)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: args[0],
			userLen: timespecPayloadStructSize,
			data:    tvData,
		})
		enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: timePayloadTimezoneSize,
			data:    tzData,
		})...)
		enterEnvelope := testTLVSyscallEnvelope(t, "settimeofday", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitEnvelope := testTLVSyscallEnvelope(t, "settimeofday", bpfEventTypeExit, args, -22, nil)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		tvSection, tvOK := ev.handlerContext.PayloadStruct(0, handler.PayloadDirectionIn)
		tzSection, tzOK := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		if !tvOK || !bytes.Equal(tvSection, tvData) {
			t.Fatalf("settimeofday timeval section = %x, %v; want pending enter TLV struct", tvSection, tvOK)
		}
		if !tzOK || !bytes.Equal(tzSection, tzData) {
			t.Fatalf("settimeofday timezone section = %x, %v; want pending enter TLV struct", tzSection, tzOK)
		}
	})
}
