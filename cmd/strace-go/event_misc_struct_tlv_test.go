package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesMiscStructTLVSections(t *testing.T) {
	exitCases := []struct {
		name       string
		args       [6]uint64
		argIndex   uint16
		structSize int
		fill       byte
	}{
		{name: "uname", args: [6]uint64{0x1000}, argIndex: 0, structSize: utsnamePayloadStructSize, fill: 0x31},
		{name: "sysinfo", args: [6]uint64{0x2000}, argIndex: 0, structSize: sysinfoPayloadStructSize, fill: 0x32},
		{name: "getrlimit", args: [6]uint64{7, 0x3000}, argIndex: 1, structSize: rlimitPayloadStructSize, fill: 0x33},
	}
	for _, tt := range exitCases {
		t.Run(tt.name, func(t *testing.T) {
			assertMiscStructExitTLVSection(t, tt.name, tt.args, tt.argIndex, tt.structSize, tt.fill)
		})
	}

	t.Run("setrlimit", func(t *testing.T) {
		args := [6]uint64{7, 0x4000}
		assertMiscStructEnterTLVMergedOnExit(t, "setrlimit", args, 1, rlimitPayloadStructSize, 0x44)
	})

	t.Run("prlimit64", func(t *testing.T) {
		args := [6]uint64{0, 7, 0x5000, 0x6000}
		assertPrlimitStructTLVSectionsMerged(t, args)
	})
}

func assertMiscStructExitTLVSection(
	t *testing.T,
	syscallName string,
	args [6]uint64,
	argIndex uint16,
	structSize int,
	fill byte,
) {
	t.Helper()
	session := miscStructTLVSession(syscallName)
	structData := bytes.Repeat([]byte{fill}, structSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     argIndex,
		userPtr: args[argIndex],
		userLen: uint32(structSize),
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

func assertMiscStructEnterTLVMergedOnExit(
	t *testing.T,
	syscallName string,
	args [6]uint64,
	argIndex uint16,
	structSize int,
	fill byte,
) {
	t.Helper()
	session := miscStructTLVSession(syscallName)
	structData := bytes.Repeat([]byte{fill}, structSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     argIndex,
		userPtr: args[argIndex],
		userLen: uint32(structSize),
		data:    structData,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, syscallName, bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	exitEnvelope := testTLVSyscallEnvelope(t, syscallName, bpfEventTypeExit, args, 0, nil)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	section, ok := ev.handlerContext.Section(int(argIndex), handler.PayloadKindStruct)
	if !ok || section.Direction != handler.PayloadDirectionIn || !bytes.Equal(section.Data, structData) {
		t.Fatalf("%s IN struct section = %+v, %v; want pending enter TLV struct", syscallName, section, ok)
	}
}

func assertPrlimitStructTLVSectionsMerged(t *testing.T, args [6]uint64) {
	t.Helper()
	session := miscStructTLVSession("prlimit64")
	newLimit := bytes.Repeat([]byte{0x55}, rlimitPayloadStructSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     2,
		userPtr: args[2],
		userLen: rlimitPayloadStructSize,
		data:    newLimit,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "prlimit64", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	oldLimit := bytes.Repeat([]byte{0x66}, rlimitPayloadStructSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     3,
		userPtr: args[3],
		userLen: rlimitPayloadStructSize,
		data:    oldLimit,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "prlimit64", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
	newSection, newOK := ev.handlerContext.Section(2, handler.PayloadKindStruct)
	oldSection, oldOK := ev.handlerContext.Section(3, handler.PayloadKindStruct)
	if !newOK || newSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(newSection.Data, newLimit) {
		t.Fatalf("prlimit64 new rlimit section = %+v, %v; want pending enter IN struct", newSection, newOK)
	}
	if !oldOK || oldSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(oldSection.Data, oldLimit) {
		t.Fatalf("prlimit64 old rlimit section = %+v, %v; want exit OUT struct", oldSection, oldOK)
	}
}

func miscStructTLVSession(syscallName string) *traceSession {
	return newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"--event-format=json", "-e", "trace=" + syscallName, "/bin/true"}), traceSessionDeps{
		TargetPID: 101,
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
		State:     newTraceState(),
	})
}
