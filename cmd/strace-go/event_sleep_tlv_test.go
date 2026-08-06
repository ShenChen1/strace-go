package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesSleepTLVSections(t *testing.T) {
	t.Run("nanosleep success keeps enter request", func(t *testing.T) {
		assertSleepTLVSections(t, "nanosleep", [6]uint64{0x1000, 0x2000}, 0, 1, 0, false)
	})
	t.Run("nanosleep interrupted adds remaining", func(t *testing.T) {
		assertSleepTLVSections(t, "nanosleep", [6]uint64{0x1100, 0x2200}, 0, 1, -4, true)
	})
	t.Run("clock_nanosleep interrupted uses arg2 and arg3", func(t *testing.T) {
		assertSleepTLVSections(t, "clock_nanosleep", [6]uint64{1, 0, 0x3300, 0x4400}, 2, 3, -516, true)
	})
}

func assertSleepTLVSections(
	t *testing.T,
	syscallName string,
	args [6]uint64,
	inArg uint16,
	outArg uint16,
	ret int64,
	wantOut bool,
) {
	t.Helper()
	session := miscStructTLVSession(syscallName)
	inData := bytes.Repeat([]byte{0x35}, timespecPayloadStructSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     inArg,
		userPtr: args[inArg],
		userLen: timespecPayloadStructSize,
		data:    inData,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, syscallName, bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	outData := bytes.Repeat([]byte{0x53}, timespecPayloadStructSize)
	var exitPayload []byte
	if wantOut {
		exitPayload = payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     outArg,
			userPtr: args[outArg],
			userLen: timespecPayloadStructSize,
			data:    outData,
		})
	}
	exitEnvelope := testTLVSyscallEnvelope(t, syscallName, bpfEventTypeExit, args, ret, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	inSection, inOK := ev.handlerContext.PayloadStruct(int(inArg), handler.PayloadDirectionIn)
	if !inOK || !bytes.Equal(inSection, inData) {
		t.Fatalf("%s IN timespec section = %x, %v; want pending enter TLV struct", syscallName, inSection, inOK)
	}
	outSection, outOK := ev.handlerContext.PayloadStruct(int(outArg), handler.PayloadDirectionOut)
	if wantOut {
		if !outOK || !bytes.Equal(outSection, outData) {
			t.Fatalf("%s OUT timespec section = %x, %v; want interrupted exit TLV struct", syscallName, outSection, outOK)
		}
		return
	}
	if outOK {
		t.Fatalf("%s OUT timespec section unexpectedly present: %x", syscallName, outSection)
	}
}
