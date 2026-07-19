package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesSetxattrTLVSections(t *testing.T) {
	session := miscStructTLVSession("setxattr")
	args := [6]uint64{0x1000, 0x2000, 0x3000, 3}
	pathData := []byte("/tmp/a\x00")
	nameData := []byte("user.k\x00")
	valueData := []byte("abc")
	enterPayload := xattrDirectTLVString(t, 0, args[0], pathData)
	enterPayload = append(enterPayload, xattrDirectTLVString(t, 1, args[1], nameData)...)
	enterPayload = append(enterPayload, xattrDirectTLVBytes(t, 2, 0, args[2], valueData)...)
	enterRaw := miscStructTLVEvent(t, "setxattr", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "setxattr", bpfEventTypeExit, args, -1, nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, handler.PayloadDirectionIn, pathData)
	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, handler.PayloadDirectionIn, nameData)
	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindBytes, handler.PayloadDirectionIn, valueData)
}

func TestSyscallEventContextMergesFgetxattrTLVSections(t *testing.T) {
	session := miscStructTLVSession("fgetxattr")
	args := [6]uint64{3, 0x2000, 0x3000, 4}
	nameData := []byte("user.k\x00")
	valueData := []byte("data")
	enterPayload := xattrDirectTLVString(t, 1, args[1], nameData)
	enterRaw := miscStructTLVEvent(t, "fgetxattr", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitPayload := xattrDirectTLVBytes(t, 2, payloadTLVFlagDirectionOut, args[2], valueData)
	exitRaw := miscStructTLVEvent(t, "fgetxattr", bpfEventTypeExit, args, 4, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindString, handler.PayloadDirectionIn, nameData)
	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 2, handler.PayloadKindBytes, handler.PayloadDirectionOut, valueData)
}

func TestSyscallEventContextMergesListxattrTLVSections(t *testing.T) {
	session := miscStructTLVSession("listxattr")
	args := [6]uint64{0x1000, 0x3000, 13}
	pathData := []byte("/tmp/a\x00")
	listData := []byte("user.a\x00user.b")
	enterPayload := xattrDirectTLVString(t, 0, args[0], pathData)
	enterRaw := miscStructTLVEvent(t, "listxattr", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitPayload := xattrDirectTLVBytes(t, 1, payloadTLVFlagDirectionOut, args[1], listData)
	exitRaw := miscStructTLVEvent(t, "listxattr", bpfEventTypeExit, args, 13, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 0, handler.PayloadKindString, handler.PayloadDirectionIn, pathData)
	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindBytes, handler.PayloadDirectionOut, listData)
}

func TestSyscallEventContextMergesFlistxattrExitTLVSection(t *testing.T) {
	session := miscStructTLVSession("flistxattr")
	args := [6]uint64{3, 0x3000, 6}
	enterRaw := miscStructTLVEvent(t, "flistxattr", bpfEventTypeEnter, args, 0, nil)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	listData := []byte("names1")
	exitPayload := xattrDirectTLVBytes(t, 1, payloadTLVFlagDirectionOut, args[1], listData)
	exitRaw := miscStructTLVEvent(t, "flistxattr", bpfEventTypeExit, args, 6, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	assertXattrDirectSection(t, ev.handlerContext.PayloadSections, 1, handler.PayloadKindBytes, handler.PayloadDirectionOut, listData)
}

func xattrDirectTLVString(t *testing.T, arg uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}

func xattrDirectTLVBytes(t *testing.T, arg uint16, flags uint16, userPtr uint64, data []byte) []byte {
	t.Helper()
	return payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   flags,
		arg:     arg,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}

func assertXattrDirectSection(
	t *testing.T,
	sections []handler.PayloadSection,
	argIndex int,
	kind handler.PayloadKind,
	direction handler.PayloadDirection,
	wantData []byte,
) {
	t.Helper()
	for _, section := range sections {
		if section.ArgIndex == argIndex && section.Kind == kind && section.Direction == direction {
			if !bytes.Equal(section.Data, wantData) {
				t.Fatalf("xattr section arg %d = %+v; want data %v", argIndex, section, wantData)
			}
			return
		}
	}
	t.Fatalf("missing xattr section arg %d kind %s direction %s in %+v", argIndex, kind, direction, sections)
}
