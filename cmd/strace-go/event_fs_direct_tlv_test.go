package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesMountTLVSections(t *testing.T) {
	session := miscStructTLVSession("mount")
	args := [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000}
	sourceData := []byte("/dev/sda1\x00")
	targetData := []byte("/mnt\x00")
	typeData := []byte("ext4\x00")
	dataData := []byte("rw\x00")
	enterPayload := fsDirectTLVString(t, 0, args[0], sourceData)
	enterPayload = append(enterPayload, fsDirectTLVString(t, 1, args[1], targetData)...)
	enterPayload = append(enterPayload, fsDirectTLVString(t, 2, args[2], typeData)...)
	enterPayload = append(enterPayload, fsDirectTLVString(t, 4, args[4], dataData)...)
	enterEnvelope := testTLVSyscallEnvelope(t, "mount", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "mount", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, sourceData)
	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, targetData)
	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindString, typeData)
	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 4, handler.PayloadKindString, dataData)
}

func TestSyscallEventContextMergesUmountTLVSection(t *testing.T) {
	session := miscStructTLVSession("umount2")
	args := [6]uint64{0x1000, 0}
	targetData := []byte("/mnt\x00")
	enterPayload := fsDirectTLVString(t, 0, args[0], targetData)
	enterEnvelope := testTLVSyscallEnvelope(t, "umount2", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "umount2", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, targetData)
}

func TestSyscallEventContextMergesFsconfigStringTLVSections(t *testing.T) {
	session := miscStructTLVSession("fsconfig")
	args := [6]uint64{3, 1, 0x1000, 0x2000, 0}
	keyData := []byte("key\x00")
	valueData := []byte("value\x00")
	enterPayload := fsDirectTLVString(t, 2, args[2], keyData)
	enterPayload = append(enterPayload, fsDirectTLVString(t, 3, args[3], valueData)...)
	enterEnvelope := testTLVSyscallEnvelope(t, "fsconfig", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "fsconfig", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindString, keyData)
	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 3, handler.PayloadKindString, valueData)
}

func TestSyscallEventContextMergesFsconfigBinaryTLVSections(t *testing.T) {
	session := miscStructTLVSession("fsconfig")
	args := [6]uint64{3, 2, 0x1000, 0x2000, 3}
	keyData := []byte("blob\x00")
	valueData := []byte{1, 2, 3}
	enterPayload := fsDirectTLVString(t, 2, args[2], keyData)
	enterPayload = append(enterPayload, fsDirectTLVBytes(t, 3, args[3], valueData)...)
	enterEnvelope := testTLVSyscallEnvelope(t, "fsconfig", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "fsconfig", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindString, keyData)
	assertFSDirectSection(t, ev.handlerContext.PayloadSections, 3, handler.PayloadKindBytes, valueData)
}

func fsDirectTLVString(t *testing.T, arg uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}

func fsDirectTLVBytes(t *testing.T, arg uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}

func assertFSDirectSection(
	t *testing.T,
	sections []handler.PayloadSection,
	argIndex int,
	kind handler.PayloadKind,
	wantData []byte,
) {
	t.Helper()
	for _, section := range sections {
		if section.ArgIndex == argIndex && section.Kind == kind {
			if section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, wantData) {
				t.Fatalf("fs section arg %d = %+v; want IN %s %v", argIndex, section, kind, wantData)
			}
			return
		}
	}
	t.Fatalf("missing fs section arg %d kind %s in %+v", argIndex, kind, sections)
}
