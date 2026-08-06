package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesIoctlDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("ioctl")
	args := [6]uint64{3, ioctlTestCmdSize(32), 0x1000}
	enterData := bytes.Repeat([]byte{0x11}, 32)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(enterData)),
		data:    enterData,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "ioctl", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitData := bytes.Repeat([]byte{0x22}, 32)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(exitData)),
		data:    exitData,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "ioctl", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	requireIoctlDirectSection(t, ev, handler.PayloadDirectionIn, enterData)
	requireIoctlDirectSection(t, ev, handler.PayloadDirectionOut, exitData)
}

func requireIoctlDirectSection(
	t *testing.T,
	ev syscallEventContext,
	direction handler.PayloadDirection,
	want []byte,
) {
	t.Helper()
	section, ok := ev.handlerContext.PayloadBytes(2, direction)
	if !ok || !bytes.Equal(section, want) {
		t.Fatalf("ioctl %s section = %v, %v; want direct TLV bytes", direction, section, ok)
	}
}
