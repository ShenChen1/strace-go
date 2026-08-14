package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestTraceStateEnterUpdateCarriesSemanticPayloadSections(t *testing.T) {
	state := newTraceState()
	path := []byte("typed.txt\x00")
	envelope := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      syscallIDByName(t, "openat"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		payload: []handler.PayloadSection{{
			Kind:     handler.PayloadKindString,
			ArgIndex: 1,
			Data:     path,
		}},
	}

	update := state.handleEnvelope(envelope)

	if update.kind != traceStateSyscallEnter {
		t.Fatalf("update kind = %d, want enter", update.kind)
	}
	if len(update.payloadSections) != 1 || string(update.payloadSections[0].Data) != "typed.txt\x00" {
		t.Fatalf("enter update payload sections = %+v, want semantic path section", update.payloadSections)
	}
	path[0] = 'X'
	if len(state.pendingSyscalls[101].payloadSections) != 1 {
		t.Fatalf("pending payload sections = %+v, want cached enter payload", state.pendingSyscalls[101].payloadSections)
	}
	if got := string(state.pendingSyscalls[101].payloadSections[0].Data); got != "typed.txt\x00" {
		t.Fatalf("pending payload data = %q, want owned enter snapshot", got)
	}
}

func TestTraceStateTransfersPendingPayloadOnExit(t *testing.T) {
	state := newTraceState()
	path := []byte("transfer.txt\x00")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      syscallIDByName(t, "openat"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		payload: []handler.PayloadSection{{
			Kind:     handler.PayloadKindString,
			ArgIndex: 1,
			Data:     path,
		}},
	}
	state.handleEnvelope(enter)
	owned := state.pendingSyscalls[101]
	if owned == nil || len(owned.payloadSections[0].Data) == 0 {
		t.Fatal("enter did not create owned pending payload")
	}
	wantPID, wantSysID := owned.pid, owned.sysID
	ownedData := owned.payloadSections[0].Data

	exit := enter
	exit.eventType = bpfEventTypeExit
	update := state.handleEnvelope(exit)
	if update.pendingEnter == nil || update.pendingEnter.pid != wantPID || update.pendingEnter.sysID != wantSysID {
		t.Fatalf("exit snapshot = %+v, want a detached pending view", update.pendingEnter)
	}
	if len(state.reusablePending) != 1 || state.reusablePending[0] != owned {
		t.Fatal("exit did not recycle the mutable pending owner")
	}
	if &update.pendingEnter.payloadSections[0].Data[0] != &ownedData[0] {
		t.Fatal("exit copied owned payload data during pending transfer")
	}
}

func TestTraceStateExitSnapshotSurvivesPendingOwnerReuse(t *testing.T) {
	state := newTraceState()
	sysID := syscallIDByName(t, "openat")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      sysID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  100,
		args:       [6]uint64{rawAtFdcwd, 0x1000},
		payload:    []handler.PayloadSection{{Kind: handler.PayloadKindString, ArgIndex: 1, Data: []byte("old.txt\x00")}},
	}
	state.handleEnvelope(enter)
	owner := state.pendingSyscalls[101]
	if owner == nil {
		t.Fatal("enter did not create pending owner")
	}

	exit := enter
	exit.eventType = bpfEventTypeExit
	update := state.handleEnvelope(exit)
	if update.pendingEnter == nil {
		t.Fatal("exit did not produce an enter snapshot")
	}
	if len(state.reusablePending) != 1 || state.reusablePending[0] != owner {
		t.Fatalf("pending owner was not recycled immediately: reusable=%p owner=%p", state.reusablePending, owner)
	}

	nextEnter := enter
	nextEnter.sysID = syscallIDByName(t, "getpid")
	nextEnter.enterTime = 200
	nextEnter.payload = nil
	state.handleEnvelope(nextEnter)
	if state.pendingSyscalls[101] != owner {
		t.Fatal("next enter did not reuse the pending owner")
	}
	if update.pendingEnter.sysID != sysID || string(update.pendingEnter.payloadSections[0].Data) != "old.txt\x00" {
		t.Fatalf("exit snapshot changed after owner reuse: %+v", update.pendingEnter)
	}

	state.releaseTraceStateUpdate(update)
	if len(state.reusableSnapshots) != 1 || len(state.reusableSnapshots[0].payloadSections) != 0 {
		t.Fatalf("released snapshot pool = %+v, want one cleared snapshot", state.reusableSnapshots)
	}
}

func TestTraceStateMergesMultipleEnterPayloadSections(t *testing.T) {
	state := newTraceState()
	sysID := syscallIDByName(t, "process_vm_writev")
	first := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      sysID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		payload: []handler.PayloadSection{{
			Kind:     handler.PayloadKindIovec,
			ArgIndex: 1,
			Data:     []byte("iovec"),
		}},
	}
	second := first
	second.payload = []handler.PayloadSection{{
		Kind:     handler.PayloadKindBytes,
		ArgIndex: 120,
		Data:     []byte("base"),
	}}

	state.handleEnvelope(first)
	state.handleEnvelope(second)

	pending := state.pendingSyscalls[101]
	if pending == nil {
		t.Fatal("pending syscall missing")
	}
	if len(pending.payloadSections) != 2 {
		t.Fatalf("payload sections = %+v, want iovec and nested base", pending.payloadSections)
	}
	if string(pending.payloadSections[0].Data) != "iovec" || string(pending.payloadSections[1].Data) != "base" {
		t.Fatalf("merged payload data = %+v", pending.payloadSections)
	}
}

func TestTraceStateMergesExitFragmentPayloadSections(t *testing.T) {
	state := newTraceState()
	sysID := syscallIDByName(t, "recvmmsg")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      sysID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		payload: []handler.PayloadSection{{
			Kind:     handler.PayloadKindIovec,
			ArgIndex: 1,
			Data:     []byte("mmsg"),
		}},
	}
	fragment := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      sysID,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagExitFragment | bpfEventFlagPayloadTLV,
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  120,
			Data:      []byte("base"),
		}},
	}
	exit := fragment
	exit.eventFlags = 0
	exit.payload = nil

	state.handleEnvelope(enter)
	fragmentUpdate := state.handleEnvelope(fragment)
	if fragmentUpdate.kind != traceStateSyscallFragment {
		t.Fatalf("fragment update kind = %d, want fragment", fragmentUpdate.kind)
	}
	pending := state.pendingSyscalls[101]
	if pending == nil || len(pending.payloadSections) != 2 {
		t.Fatalf("pending after fragment = %+v, want merged enter and exit payloads", pending)
	}
	exitUpdate := state.handleEnvelope(exit)
	if exitUpdate.pendingEnter == nil || len(state.pendingSyscalls) != 0 {
		t.Fatalf("exit update = %+v pending=%d, want final consume", exitUpdate, len(state.pendingSyscalls))
	}
	if len(exitUpdate.pendingEnter.payloadSections) != 2 {
		t.Fatalf("paired payload sections = %+v, want merged fragment payload", exitUpdate.pendingEnter.payloadSections)
	}
}

func TestTraceStateExitUpdateCarriesSemanticPayloadSections(t *testing.T) {
	state := newTraceState()
	envelope := traceEventEnvelope{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     syscallIDByName(t, "read"),
		eventType: bpfEventTypeExit,
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  1,
			Data:      []byte("typed"),
		}},
	}

	update := state.handleEnvelope(envelope)

	if update.kind != traceStateSyscallExit {
		t.Fatalf("update kind = %d, want exit", update.kind)
	}
	if len(update.payloadSections) != 1 || string(update.payloadSections[0].Data) != "typed" {
		t.Fatalf("exit update payload sections = %+v, want semantic bytes section", update.payloadSections)
	}
}

func TestTraceStateExitUpdateCarriesSyscallResultView(t *testing.T) {
	state := newTraceState()
	envelope := traceEventEnvelope{
		valid:        true,
		pid:          101,
		tid:          102,
		sysID:        syscallIDByName(t, "openat"),
		eventType:    bpfEventTypeExit,
		ret:          -2,
		duration:     55,
		ptr:          0x1234,
		stackID:      7,
		probeRetExit: -1,
	}

	update := state.handleEnvelope(envelope)
	view := update.syscallView

	if view.ret != -2 || view.duration != 55 || view.ptr != 0x1234 ||
		view.stackID != 7 || view.probeRetExit != -1 {
		t.Fatalf("exit syscall view = %+v, want result fields from envelope", view)
	}
}
