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
	enterEnvelope := testTLVSyscallEnvelope(t, "mkdir", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "mkdir", bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
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

func TestSyscallEventContextPrefersPathOnlyExitRetryTLVSection(t *testing.T) {
	session := miscStructTLVSession("chdir")
	args := [6]uint64{0x2000}
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:     payloadTLVKindString,
		arg:      0,
		userPtr:  args[0],
		probeRet: -14,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "chdir", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitData := []byte("fork-f.child\x00")
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(exitData)),
		data:    exitData,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "chdir", bpfEventTypeExit, args, -2, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	section, ok := ev.handlerContext.Section(0, handler.PayloadKindString)
	if !ok || section.ProbeRet != 0 || !bytes.Equal(section.Data, exitData) {
		t.Fatalf("chdir retry path section = %+v, %v; want successful exit retry string TLV", section, ok)
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
	enterEnvelope := testTLVSyscallEnvelope(t, "rename", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "rename", bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
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

func TestSyscallEventContextPrefersDualPathExitRetryTLVSections(t *testing.T) {
	session := miscStructTLVSession("rename")
	args := [6]uint64{0x2000, 0x3000}
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:     payloadTLVKindString,
		arg:      0,
		userPtr:  args[0],
		probeRet: -14,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:     payloadTLVKindString,
		arg:      1,
		userPtr:  args[1],
		probeRet: -14,
	})...)
	session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, "rename", bpfEventTypeEnter, args, 0, enterPayload))

	oldExitData := []byte("old-exit\x00")
	newExitData := []byte("new-exit\x00")
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(oldExitData)),
		data:    oldExitData,
	})
	exitPayload = append(exitPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(newExitData)),
		data:    newExitData,
	})...)
	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(
		t,
		"rename",
		bpfEventTypeExit,
		args,
		-2,
		exitPayload))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	oldSection, oldOK := ev.handlerContext.Section(0, handler.PayloadKindString)
	newSection, newOK := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !oldOK || oldSection.ProbeRet != 0 || !bytes.Equal(oldSection.Data, oldExitData) {
		t.Fatalf("rename old retry path section = %+v, %v; want exit snapshot", oldSection, oldOK)
	}
	if !newOK || newSection.ProbeRet != 0 || !bytes.Equal(newSection.Data, newExitData) {
		t.Fatalf("rename new retry path section = %+v, %v; want exit snapshot", newSection, newOK)
	}
}
