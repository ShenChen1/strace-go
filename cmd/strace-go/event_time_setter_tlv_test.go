package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

func TestSyscallEventContextUsesTimeSetterTLVSections(t *testing.T) {
	t.Run("clock_settime timespec", func(t *testing.T) {
		args := [6]uint64{0, 0x1000}
		session := miscStructTLVSession("clock_settime")
		inData := bytes.Repeat([]byte{0x27}, timespecPayloadStructSize)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: timespecPayloadStructSize,
			data:    inData,
		})
		enterEnvelope := testTLVSyscallEnvelope(t, "clock_settime", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitEnvelope := testTLVSyscallEnvelope(t, "clock_settime", bpfEventTypeExit, args, -22, nil)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		section, ok := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		if !ok || !bytes.Equal(section, inData) {
			t.Fatalf("clock_settime IN section = %x, %v; want pending enter TLV struct", section, ok)
		}
	})

	t.Run("settimeofday timeval and timezone", func(t *testing.T) {
		args := [6]uint64{0x2000, 0x3000}
		session := miscStructTLVSession("settimeofday")
		tvData := bytes.Repeat([]byte{0x16}, timespecPayloadStructSize)
		tzData := bytes.Repeat([]byte{0x08}, timePayloadTimezoneSize)
		enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: args[0],
			userLen: timespecPayloadStructSize,
			data:    tvData,
		})
		enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: args[1],
			userLen: timePayloadTimezoneSize,
			data:    tzData,
		})...)
		enterEnvelope := testTLVSyscallEnvelope(t, "settimeofday", bpfEventTypeEnter, args, 0, enterPayload)
		session.traceState().handleEnvelope(enterEnvelope)

		exitEnvelope := testTLVSyscallEnvelope(t, "settimeofday", bpfEventTypeExit, args, -22, nil)
		exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
		ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)
		tvSection, tvOK := ev.handlerContext.PayloadStruct(0, handler.PayloadDirectionIn)
		tzSection, tzOK := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionIn)
		if !tvOK || !bytes.Equal(tvSection, tvData) {
			t.Fatalf("settimeofday timeval section = %x, %v; want pending enter TLV struct", tvSection, tvOK)
		}
		if !tzOK || !bytes.Equal(tzSection, tzData) {
			t.Fatalf("settimeofday timezone section = %x, %v; want pending enter TLV struct", tzSection, tzOK)
		}
	})
}

func TestTextStandaloneClockGettimeExitUsesOutTLV(t *testing.T) {
	session := newTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=clock_gettime", "/bin/true"}), traceSessionDeps{
		TargetPID: 101,
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})
	args := [6]uint64{1, 0x2000}
	outData := bytes.Repeat([]byte{0x41}, timespecPayloadStructSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: timespecPayloadStructSize,
		data:    outData,
	})
	update := session.traceState().handleEnvelope(testTLVSyscallEnvelope(
		t,
		"clock_gettime",
		bpfEventTypeExit,
		args,
		0,
		exitPayload,
	))
	if update.deferred || update.pendingEnter == nil {
		t.Fatalf("clock_gettime text exit update = %+v, want synthetic enter", update)
	}
	ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, update.payloadSections)
	if ev.handlerContext == nil {
		t.Fatal("clock_gettime text exit did not build handler context")
	}
	got, ok := ev.handlerContext.PayloadStruct(1, handler.PayloadDirectionOut)
	if !ok || !bytes.Equal(got, outData) {
		t.Fatalf("clock_gettime OUT TLV = %x, %v; want exit snapshot", got, ok)
	}
	if result := ev.handleWith(nil); len(result.ArgParts) != 2 {
		t.Fatalf("clock_gettime handler result = %+v, want clock id and timespec", result)
	}
	ev.releaseHandlerContext()
	state := session.traceState()
	state.releaseTraceStateUpdate(update)

	failedUpdate := state.handleEnvelope(testTLVSyscallEnvelope(
		t,
		"clock_gettime",
		bpfEventTypeExit,
		args,
		-14,
		nil,
	))
	if failedUpdate.deferred || failedUpdate.pendingEnter == nil {
		t.Fatalf("failed clock_gettime text exit update = %+v, want synthetic enter", failedUpdate)
	}
	failedEvent := newSyscallEventContextFromView(
		session,
		failedUpdate.syscallView,
		101,
		failedUpdate.pendingEnter,
		failedUpdate.payloadSections,
	)
	failedResult := failedEvent.handleWith(nil)
	if len(failedResult.ArgParts) != 2 || !strings.Contains(failedResult.ArgParts[1], "0x2000") {
		t.Fatalf("failed clock_gettime handler result = %+v, want pointer fallback", failedResult)
	}
	failedEvent.releaseHandlerContext()
	state.releaseTraceStateUpdate(failedUpdate)
}
