package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesSmallStructTLVSections(t *testing.T) {
	t.Run("arch_prctl exit out word", func(t *testing.T) {
		args := [6]uint64{0x1003, 0x7000}
		assertSmallStructExitTLVSection(t, "arch_prctl", args, 1, 0x71)
	})

	t.Run("get_robust_list exit out words", func(t *testing.T) {
		args := [6]uint64{0, 0x8000, 0x9000}
		session := miscStructTLVSession("get_robust_list")
		headData := bytes.Repeat([]byte{0x81}, 8)
		lenData := bytes.Repeat([]byte{0x82}, 8)
		payload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: args[1],
			userLen: 8,
			data:    headData,
		})
		payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     2,
			userPtr: args[2],
			userLen: 8,
			data:    lenData,
		})...)
		exitEnvelope := testTLVSyscallEnvelope(t, "get_robust_list", bpfEventTypeExit, args, 0, payload)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

		headSection, headOK := ev.handlerContext.Section(1, handler.PayloadKindStruct)
		lenSection, lenOK := ev.handlerContext.Section(2, handler.PayloadKindStruct)
		if !headOK || headSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(headSection.Data, headData) {
			t.Fatalf("get_robust_list head section = %+v, %v; want exit OUT struct", headSection, headOK)
		}
		if !lenOK || lenSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(lenSection.Data, lenData) {
			t.Fatalf("get_robust_list len section = %+v, %v; want exit OUT struct", lenSection, lenOK)
		}
	})

	t.Run("sendfile enter and exit words", func(t *testing.T) {
		args := [6]uint64{5, 4, 0xa000, 4}
		session := miscStructTLVSession("sendfile")
		enterData := bytes.Repeat([]byte{0xa1}, 8)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     2,
			userPtr: args[2],
			userLen: 8,
			data:    enterData,
		})
		enterEnvelope := testTLVSyscallEnvelope(t, "sendfile", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitData := bytes.Repeat([]byte{0xa2}, 8)
		exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     2,
			userPtr: args[2],
			userLen: 8,
			data:    exitData,
		})
		exitEnvelope := testTLVSyscallEnvelope(t, "sendfile", bpfEventTypeExit, args, 4, exitPayload)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		enterSection, enterOK := ev.handlerContext.PayloadStruct(2, handler.PayloadDirectionIn)
		exitSection, exitOK := ev.handlerContext.PayloadStruct(2, handler.PayloadDirectionOut)
		if !enterOK || !bytes.Equal(enterSection, enterData) {
			t.Fatalf("sendfile enter section = %x, %v; want pending enter struct", enterSection, enterOK)
		}
		if !exitOK || !bytes.Equal(exitSection, exitData) {
			t.Fatalf("sendfile exit section = %x, %v; want exit OUT struct", exitSection, exitOK)
		}
	})

	t.Run("copy_file_range enter words", func(t *testing.T) {
		args := [6]uint64{4, 0xb000, 5, 0xc000, 4, 0}
		session := miscStructTLVSession("copy_file_range")
		inData := bytes.Repeat([]byte{0xb1}, 8)
		outData := bytes.Repeat([]byte{0xc1}, 8)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: 8,
			data:    inData,
		})
		enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     3,
			userPtr: args[3],
			userLen: 8,
			data:    outData,
		})...)
		enterEnvelope := testTLVSyscallEnvelope(t, "copy_file_range", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitEnvelope := testTLVSyscallEnvelope(t, "copy_file_range", bpfEventTypeExit, args, 4, nil)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		inSection, inOK := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		outSection, outOK := ev.handlerContext.PayloadStruct(3, handler.PayloadDirectionIn)
		if !inOK || !bytes.Equal(inSection, inData) {
			t.Fatalf("copy_file_range off_in section = %x, %v; want pending enter struct", inSection, inOK)
		}
		if !outOK || !bytes.Equal(outSection, outData) {
			t.Fatalf("copy_file_range off_out section = %x, %v; want pending enter struct", outSection, outOK)
		}
	})
}

func assertSmallStructExitTLVSection(t *testing.T, syscallName string, args [6]uint64, argIndex uint16, fill byte) {
	t.Helper()
	session := miscStructTLVSession(syscallName)
	structData := bytes.Repeat([]byte{fill}, 8)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     argIndex,
		userPtr: args[argIndex],
		userLen: 8,
		data:    structData,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, syscallName, bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(int(argIndex), handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionOut || !bytes.Equal(section.Data, structData) {
		t.Fatalf("%s OUT struct section = %+v, %v; want exit TLV struct", syscallName, section, ok)
	}
}
