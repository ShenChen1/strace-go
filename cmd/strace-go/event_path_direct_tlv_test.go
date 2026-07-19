package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesPathOnlyTLVSection(t *testing.T) {
	session := miscStructTLVSession("mkdir")
	args := [6]uint64{0x2000}
	pathData := []byte("/tmp/path-direct\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(pathData)),
		data:    pathData,
	})
	enterRaw := miscStructTLVEvent(t, "mkdir", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "mkdir", bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	section, ok := ev.handlerContext.Section(0, handler.PayloadKindString)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, pathData) {
		t.Fatalf("mkdir path section = %+v, %v; want pending enter string TLV", section, ok)
	}
}

func TestSyscallEventContextMergesDualPathTLVSections(t *testing.T) {
	session := miscStructTLVSession("rename")
	args := [6]uint64{0x2000, 0x3000}
	oldData := []byte("old-direct\x00")
	newData := []byte("new-direct\x00")
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(oldData)),
		data:    oldData,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(newData)),
		data:    newData,
	})...)
	enterRaw := miscStructTLVEvent(t, "rename", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "rename", bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	oldSection, oldOK := ev.handlerContext.Section(0, handler.PayloadKindString)
	newSection, newOK := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !oldOK || oldSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(oldSection.Data, oldData) {
		t.Fatalf("rename old path section = %+v, %v; want pending enter string TLV", oldSection, oldOK)
	}
	if !newOK || newSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(newSection.Data, newData) {
		t.Fatalf("rename new path section = %+v, %v; want pending enter string TLV", newSection, newOK)
	}
}
