package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesAioSetupDirectTLVSection(t *testing.T) {
	session := miscStructTLVSession("io_setup")
	args := [6]uint64{128, 0x1000}
	ctxData := aioTestPointerBytes(0xabc)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(ctxData)),
		data:    ctxData,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "io_setup", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionOut || !bytes.Equal(section.Data, ctxData) {
		t.Fatalf("io_setup ctx section = %+v, %v; want direct OUT struct TLV", section, ok)
	}
}

func TestSyscallEventContextMergesAioCancelDirectTLVSection(t *testing.T) {
	session := miscStructTLVSession("io_cancel")
	args := [6]uint64{0xabc, 0x2000, 0x3000}
	iocbData := aioTestIocbData(1, 0x4000, 3)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(iocbData)),
		data:    iocbData,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "io_cancel", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "io_cancel", bpfEventTypeExit, args, -22, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, iocbData) {
		t.Fatalf("io_cancel iocb section = %+v, %v; want pending enter IN struct TLV", section, ok)
	}
}

func TestSyscallEventContextMergesAioSubmitDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("io_submit")
	args := [6]uint64{0xabc, 2, 0x1000}
	pointers := append(aioTestPointerBytes(0x2000), aioTestPointerBytes(0x3000)...)
	iocb0 := aioTestIocbData(1, 0x4000, 3)
	iocb1 := aioTestIocbData(0, 0x5000, 4)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     2,
		userPtr: args[2],
		userLen: uint32(len(pointers)),
		data:    pointers,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     handler.AioSubmitIocbPayloadArgBase,
		userPtr: 0x2000,
		userLen: uint32(len(iocb0)),
		data:    iocb0,
	})...)
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     handler.AioSubmitIocbPayloadArgBase + 1,
		userPtr: 0x3000,
		userLen: uint32(len(iocb1)),
		data:    iocb1,
	})...)
	enterEnvelope := testTLVSyscallEnvelope(t, "io_submit", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, "io_submit", bpfEventTypeExit, args, 2, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	requireAioDirectSection(t, ev, 2, handler.PayloadDirectionIn, pointers)
	requireAioDirectSection(t, ev, handler.AioSubmitIocbPayloadArgBase, handler.PayloadDirectionIn, iocb0)
	requireAioDirectSection(t, ev, handler.AioSubmitIocbPayloadArgBase+1, handler.PayloadDirectionIn, iocb1)
}

func TestSyscallEventContextMergesAioGeteventsDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("io_getevents")
	args := [6]uint64{0xabc, 0, 1, 0x2000, 0x3000}
	timeout := aioTestTimespecData(5, 6)
	events := aioTestIoEventData(0x11, 0x22, 3, 4)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     4,
		userPtr: args[4],
		userLen: uint32(len(timeout)),
		data:    timeout,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "io_getevents", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     3,
		userPtr: args[3],
		userLen: uint32(len(events)),
		data:    events,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "io_getevents", bpfEventTypeExit, args, 1, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	requireAioDirectSection(t, ev, 4, handler.PayloadDirectionIn, timeout)
	requireAioDirectSection(t, ev, 3, handler.PayloadDirectionOut, events)
}

func TestSyscallEventContextMergesAioPgeteventsDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("io_pgetevents")
	args := [6]uint64{0xabc, 0, 1, 0x2000, 0x3000, 0x4000}
	timeout := aioTestTimespecData(5, 6)
	sigset := append(aioTestPointerBytes(0x5000), aioTestPointerBytes(8)...)
	mask := aioTestPointerBytes(1)
	events := aioTestIoEventData(0x11, 0x22, 3, 4)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     4,
		userPtr: args[4],
		userLen: uint32(len(timeout)),
		data:    timeout,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     5,
		userPtr: args[5],
		userLen: uint32(len(sigset)),
		data:    sigset,
	})...)
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     5,
		userPtr: 0x5000,
		userLen: uint32(len(mask)),
		data:    mask,
	})...)
	enterEnvelope := testTLVSyscallEnvelope(t, "io_pgetevents", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     3,
		userPtr: args[3],
		userLen: uint32(len(events)),
		data:    events,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "io_pgetevents", bpfEventTypeExit, args, 1, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)
	requireAioDirectTypedSection(t, ev, 4, handler.PayloadKindStruct, handler.PayloadDirectionIn, timeout)
	requireAioDirectTypedSection(t, ev, 5, handler.PayloadKindStruct, handler.PayloadDirectionIn, sigset)
	requireAioDirectTypedSection(t, ev, 5, handler.PayloadKindBytes, handler.PayloadDirectionIn, mask)
	requireAioDirectTypedSection(t, ev, 3, handler.PayloadKindStruct, handler.PayloadDirectionOut, events)
}

func requireAioDirectSection(t *testing.T, ev syscallEventContext, argIndex int, direction handler.PayloadDirection, want []byte) {
	requireAioDirectTypedSection(t, ev, argIndex, handler.PayloadKindStruct, direction, want)
}

func requireAioDirectTypedSection(t *testing.T, ev syscallEventContext, argIndex int, kind handler.PayloadKind, direction handler.PayloadDirection, want []byte) {
	t.Helper()
	section, ok := ev.handlerContext.Section(argIndex, kind)
	if !ok || section.Direction != direction || !bytes.Equal(section.Data, want) {
		t.Fatalf("AIO section arg %d = %+v, %v; want %s %s TLV", argIndex, section, ok, direction, kind)
	}
}
