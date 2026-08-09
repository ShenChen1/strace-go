package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesQuotaDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("quotactl")
	args := [6]uint64{0x80000700, 0x1000, 1000, 0x2000}
	special := []byte("/dev/sda1\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind: payloadTLVKindString, arg: 1, userPtr: args[1],
		userLen: uint32(len(special)), data: special,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "quotactl", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	dqblk := bytes.Repeat([]byte{0x22}, 72)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind: payloadTLVKindStruct, flags: payloadTLVFlagDirectionOut, arg: 3,
		userPtr: args[3], userLen: uint32(len(dqblk)), data: dqblk,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "quotactl", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	specialSection, specialOK := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !specialOK || specialSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(specialSection.Data, special) {
		t.Fatalf("quota special section = %+v, %v; want pending enter IN string", specialSection, specialOK)
	}
	dqblkSection, dqblkOK := ev.handlerContext.Section(3, handler.PayloadKindStruct)
	if !dqblkOK || dqblkSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(dqblkSection.Data, dqblk) {
		t.Fatalf("quota dqblk section = %+v, %v; want exit OUT struct", dqblkSection, dqblkOK)
	}
}
