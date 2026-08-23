package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
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

func TestTextStandaloneSmallStructExitUsesOutTLV(t *testing.T) {
	t.Run("arch_prctl", func(t *testing.T) {
		args := [6]uint64{0x1003, 0x7000}
		assertTextStandaloneSmallStructExit(t, "arch_prctl", args, 0, []payloadTLVTestSection{{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: args[1],
			userLen: 8,
			data:    smallStructPayloadWord(0x1234),
		}})
	})
	t.Run("get_robust_list", func(t *testing.T) {
		args := [6]uint64{0, 0x8000, 0x9000}
		assertTextStandaloneSmallStructExit(t, "get_robust_list", args, 0, []payloadTLVTestSection{
			{kind: payloadTLVKindStruct, flags: payloadTLVFlagDirectionOut, arg: 1, userPtr: args[1], userLen: 8, data: smallStructPayloadWord(0xbeef)},
			{kind: payloadTLVKindStruct, flags: payloadTLVFlagDirectionOut, arg: 2, userPtr: args[2], userLen: 8, data: smallStructPayloadWord(32)},
		})
	})
}

func assertTextStandaloneSmallStructExit(t *testing.T, name string, args [6]uint64, ret int64, sections []payloadTLVTestSection) {
	t.Helper()
	session := newTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=" + name, "/bin/true"}), traceSessionDeps{
		TargetPID: 101,
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})
	payload := payloadTLVBytesForTest(t, sections...)
	update := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, name, bpfEventTypeExit, args, ret, payload))
	if update.deferred || update.pendingEnter == nil {
		t.Fatalf("%s text exit update = %+v, want synthetic enter", name, update)
	}
	ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, update.payloadSections)
	if ev.handlerContext == nil {
		t.Fatal("standalone small-struct exit did not build handler context")
	}
	result := ev.handleWith(nil)
	wantParts := 2
	if name == "get_robust_list" {
		wantParts = 3
	}
	if len(result.ArgParts) != wantParts {
		t.Fatalf("%s handler result = %+v, want %d args", name, result, wantParts)
	}
	for _, section := range sections {
		data, ok := ev.handlerContext.PayloadStruct(int(section.arg), handler.PayloadDirectionOut)
		if !ok || !bytes.Equal(data, section.data) {
			t.Fatalf("%s arg%d payload = %x, %v; want %x", name, section.arg, data, ok, section.data)
		}
	}
	ev.releaseHandlerContext()
	state := session.traceState()
	state.releaseTraceStateUpdate(update)
}

func TestTextStandaloneSmallStructFailureFallsBackToPointers(t *testing.T) {
	for _, test := range []struct {
		name string
		args [6]uint64
	}{
		{name: "arch_prctl", args: [6]uint64{0x1003, 0x7000}},
		{name: "get_robust_list", args: [6]uint64{0, 0x8000, 0x9000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := newTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=" + test.name, "/bin/true"}), traceSessionDeps{
				TargetPID: 101,
				FDState:   newFDStateStoreFromMaps(nil, nil),
			})
			update := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, test.name, bpfEventTypeExit, test.args, -14, nil))
			if update.deferred || update.pendingEnter == nil {
				t.Fatalf("%s failed exit update = %+v, want synthetic enter", test.name, update)
			}
			ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, nil)
			result := ev.handleWith(nil)
			if len(result.ArgParts) < 2 || !strings.Contains(result.ArgParts[1], "0x") {
				t.Fatalf("%s failed result = %+v, want pointer fallback", test.name, result)
			}
			ev.releaseHandlerContext()
			state := session.traceState()
			state.releaseTraceStateUpdate(update)
		})
	}
}

func smallStructPayloadWord(value uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, value)
	return data
}
