package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestTraceStateReportsOtherTIDPendingForUnfinished(t *testing.T) {
	state := newTraceState()
	first := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	second := first
	second.tid = 102
	second.enterTime = 20

	state.handleEnvelope(first)
	update := state.handleEnvelope(second)

	if len(update.unfinished) != 1 || update.unfinished[0].tid != 101 {
		t.Fatalf("unfinished candidates = %+v, want pending TID 101", update.unfinished)
	}

	third := second
	third.eventType = bpfEventTypeExit
	third.ret = 0
	update = state.handleEnvelope(third)
	if len(update.unfinished) != 0 {
		t.Fatalf("in-flight unfinished candidates on same-TID exit = %+v, want none", update.unfinished)
	}
}

func TestTraceStateDoesNotReemitInFlightUnfinishedCandidate(t *testing.T) {
	state := newTraceState()
	first := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	state.handleEnvelope(first)

	other := first
	other.tid = 102
	other.sysID = syscallIDByName(t, "getpid")
	other.enterTime = 20
	if update := state.handleEnvelope(other); len(update.unfinished) != 1 {
		t.Fatalf("first unfinished candidates = %d, want one", len(update.unfinished))
	}

	third := other
	third.tid = 103
	third.enterTime = 30
	if update := state.handleEnvelope(third); len(update.unfinished) != 1 || update.unfinished[0].tid != 102 {
		t.Fatalf("unfinished candidates after first TID is in-flight = %+v, want only TID 102", update.unfinished)
	}
}

func TestTraceStateRequeuesUnfinishedCandidateAfterOutputFailure(t *testing.T) {
	state := newTraceState()
	first := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	state.handleEnvelope(first)
	other := first
	other.tid = 102
	other.sysID = syscallIDByName(t, "getpid")
	other.enterTime = 20
	state.handleEnvelope(other)
	state.markUnfinishedPrinted(102)
	state.requeueUnfinished(101)

	third := other
	third.tid = 103
	third.enterTime = 30
	update := state.handleEnvelope(third)
	if len(update.unfinished) != 1 || update.unfinished[0].tid != 101 {
		t.Fatalf("requeued unfinished candidates = %+v, want TID 101", update.unfinished)
	}
}

func TestTraceStateIgnoresZeroTIDForUnfinishedCandidates(t *testing.T) {
	state := newTraceState()
	state.handleEnvelope(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	})

	update := state.handleEnvelope(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        0,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  20,
	})
	if len(update.unfinished) != 0 {
		t.Fatalf("zero-TID unfinished candidates = %+v, want none", update.unfinished)
	}
}

func TestTraceStateDisablesUnfinishedCandidateIndex(t *testing.T) {
	state := newTraceState()
	state.setUnfinishedEnabled(false)
	first := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	state.handleEnvelope(first)
	second := first
	second.tid = 102
	second.sysID = syscallIDByName(t, "getpid")
	second.enterTime = 20
	if update := state.handleEnvelope(second); len(update.unfinished) != 0 {
		t.Fatalf("unfinished candidates while disabled = %+v, want none", update.unfinished)
	}
	if len(state.unqueuedUnfinished) != 0 || len(state.inFlightUnfinished) != 0 {
		t.Fatalf("disabled unfinished index = unqueued %d, in-flight %d; want empty", len(state.unqueuedUnfinished), len(state.inFlightUnfinished))
	}

	state.setUnfinishedEnabled(true)
	third := second
	third.tid = 103
	third.enterTime = 30
	update := state.handleEnvelope(third)
	if len(update.unfinished) != 2 || update.unfinished[0].tid != 101 || update.unfinished[1].tid != 102 {
		t.Fatalf("re-enabled unfinished candidates = %+v, want TIDs 101 and 102", update.unfinished)
	}
}

func TestTraceStateReturnsPendingAndTaskSnapshots(t *testing.T) {
	state := newTraceState()
	enter := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		payload: []handler.PayloadSection{{
			Kind: handler.PayloadKindBytes,
			Data: []byte("stable"),
		}},
	}
	state.handleEnvelope(enter)

	other := enter
	other.tid = 102
	other.sysID = syscallIDByName(t, "getpid")
	other.payload = nil
	update := state.handleEnvelope(other)
	if len(update.unfinished) != 1 {
		t.Fatalf("unfinished snapshot count = %d, want one", len(update.unfinished))
	}
	update.unfinished[0].unfinishedPrinted = true
	update.unfinished[0].payloadSections[0].Data[0] = 'X'
	pending := state.pendingSyscalls[101]
	if pending == nil || pending.unfinishedPrinted || string(pending.payloadSections[0].Data) != "stable" {
		t.Fatalf("pending state was aliased by snapshot: %+v", pending)
	}

	state.markUnfinishedPrinted(101)
	exit := other
	exit.eventType = bpfEventTypeExit
	update = state.handleEnvelope(exit)
	if len(update.unfinished) != 0 {
		t.Fatalf("unfinished after explicit mark = %+v, want none for TID 101", update.unfinished)
	}

	lifecycle := traceEventEnvelope{
		valid:           true,
		pid:             100,
		tid:             100,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleExec,
		args:            [6]uint64{0, 100},
	}
	lifecycleUpdate := state.handleEnvelope(lifecycle)
	lifecycleUpdate.lifecycleTask.LastAction = "mutated outside state"
	if state.tasks[100].LastAction == "mutated outside state" {
		t.Fatal("lifecycle task update aliases TraceState task map")
	}
}
