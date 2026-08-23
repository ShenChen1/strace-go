package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesPselect6DirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("pselect6")
	args := [6]uint64{8, 0x1000, 0x2000, 0, 0x3000, 0x5000}
	enterRead := []byte{0x08}
	enterTimeout := pselect6Timespec(9, 10)
	enterWrapper := pselect6WrapperBytes(0x6000, 8)
	enterMask := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	enterPayload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{kind: payloadTLVKindBytes, arg: 1, userPtr: args[1], userLen: 1, data: enterRead},
		payloadTLVTestSection{kind: payloadTLVKindStruct, arg: 4, userPtr: args[4], userLen: 16, data: enterTimeout},
		payloadTLVTestSection{kind: payloadTLVKindStruct, arg: 5, userPtr: args[5], userLen: 16, data: enterWrapper},
		payloadTLVTestSection{kind: payloadTLVKindStruct, arg: 6, userPtr: 0x6000, userLen: 8, data: enterMask},
	)
	session.traceState().handleEnvelope(
		testTLVSyscallEnvelope(t, "pselect6", bpfEventTypeEnter, args, 0, enterPayload))

	exitRead := []byte{0x00, 0x01}
	exitTimeout := pselect6Timespec(1, 2)
	exitPayload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{kind: payloadTLVKindBytes, flags: payloadTLVFlagDirectionOut, arg: 1, userPtr: args[1], userLen: 1, data: exitRead},
		payloadTLVTestSection{kind: payloadTLVKindStruct, flags: payloadTLVFlagDirectionOut, arg: 4, userPtr: args[4], userLen: 16, data: exitTimeout},
	)
	update := session.traceState().handleEnvelope(
		testTLVSyscallEnvelope(t, "pselect6", bpfEventTypeExit, args, 1, exitPayload))
	ev := newSyscallEventContextFromView(
		session,
		update.syscallView,
		101,
		update.pendingEnter,
		update.payloadSections)

	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 1, handler.PayloadDirectionIn, enterRead)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 4, handler.PayloadDirectionIn, enterTimeout)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 5, handler.PayloadDirectionIn, enterWrapper)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 6, handler.PayloadDirectionIn, enterMask)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindBytes, 1, handler.PayloadDirectionOut, exitRead)
	assertSelectDirectSection(t, ev.handlerContext.PayloadSections, handler.PayloadKindStruct, 4, handler.PayloadDirectionOut, exitTimeout)
	if !bytes.Equal(ev.handlerContext.PayloadSections[3].Data, enterMask) {
		t.Fatalf("pselect6 synthetic mask section = %x, want %x", ev.handlerContext.PayloadSections[3].Data, enterMask)
	}
}

func pselect6WrapperBytes(maskPtr uint64, size uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], maskPtr)
	binary.LittleEndian.PutUint64(data[8:16], size)
	return data
}

func pselect6Timespec(sec int64, nsec uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(data[8:16], nsec)
	return data
}
