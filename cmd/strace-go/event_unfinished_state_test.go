package main

import (
	"testing"

	"strace-go/pkg/cli"
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

func TestTraceStateSkipsStableNonBlockingUnfinishedCandidates(t *testing.T) {
	state := newTraceState()
	getpid := traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	state.handleEnvelope(getpid)

	read := getpid
	read.tid = 102
	read.sysID = syscallIDByName(t, "read")
	read.enterTime = 20
	update := state.handleEnvelope(read)

	if len(update.unfinished) != 0 {
		t.Fatalf("non-blocking unfinished candidates = %+v, want none", update.unfinished)
	}
	if len(state.correlation.pendingSyscalls) != 2 {
		t.Fatalf("pending syscalls = %d, want both enter states retained", len(state.correlation.pendingSyscalls))
	}
	if len(state.unfinished.unqueued) != 1 {
		t.Fatalf("unfinished index size = %d, want read only", len(state.unfinished.unqueued))
	}
}

func TestShouldTrackUnfinishedSyscallUsesConservativeDenylist(t *testing.T) {
	for _, name := range []string{"getpid", "gettid", "getppid", "clock_gettime", "get_robust_list"} {
		if shouldTrackUnfinishedSyscall(syscallIDByName(t, name)) {
			t.Fatalf("shouldTrackUnfinishedSyscall(%s) = true, want false", name)
		}
	}
	if !shouldTrackUnfinishedSyscall(syscallIDByName(t, "read")) {
		t.Fatal("shouldTrackUnfinishedSyscall(read) = false, want true")
	}
	if !shouldTrackUnfinishedSyscall(9999) {
		t.Fatal("unknown syscall was excluded from unfinished tracking")
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
	other.sysID = syscallIDByName(t, "read")
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

func TestTraceStateKeepsInFlightCandidateOnDuplicateEnter(t *testing.T) {
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
	other.enterTime = 20
	if update := state.handleEnvelope(other); len(update.unfinished) != 1 {
		t.Fatalf("unfinished candidates = %d, want one", len(update.unfinished))
	}
	if _, ok := state.unfinished.inFlight[101]; !ok {
		t.Fatal("first syscall was not marked in-flight")
	}

	state.handleEnvelope(first)
	if _, ok := state.unfinished.inFlight[101]; !ok {
		t.Fatal("duplicate enter moved the in-flight syscall out of its output state")
	}
	if _, ok := state.unfinished.unqueued[101]; ok {
		t.Fatal("duplicate enter requeued an in-flight syscall")
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
	second.sysID = syscallIDByName(t, "read")
	second.enterTime = 20
	if update := state.handleEnvelope(second); len(update.unfinished) != 0 {
		t.Fatalf("unfinished candidates while disabled = %+v, want none", update.unfinished)
	}
	if len(state.unfinished.unqueued) != 0 || len(state.unfinished.inFlight) != 0 {
		t.Fatalf("disabled unfinished index = unqueued %d, in-flight %d; want empty", len(state.unfinished.unqueued), len(state.unfinished.inFlight))
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

func TestTraceStateDoesNotTouchUnfinishedIndexWhenDisabled(t *testing.T) {
	state := newTraceState()
	state.setUnfinishedEnabled(false)
	state.unfinished.unqueued = map[uint32]struct{}{101: {}}
	state.unfinished.inFlight = map[uint32]struct{}{101: {}}

	state.unfinished.deleteCandidate(101)

	if len(state.unfinished.unqueued) != 1 || len(state.unfinished.inFlight) != 1 {
		t.Fatalf("disabled unfinished index was mutated: unqueued=%d in-flight=%d", len(state.unfinished.unqueued), len(state.unfinished.inFlight))
	}
}

func TestTraceStateReturnsUnfinishedViewAndTaskSnapshots(t *testing.T) {
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
	pending := state.correlation.pendingSyscalls[101]
	if pending == nil || string(pending.payloadSections[0].Data) != "stable" {
		t.Fatalf("pending state missing stable payload: %+v", pending)
	}
	if &update.unfinished[0].payloadSections[0].Data[0] != &pending.payloadSections[0].Data[0] {
		t.Fatal("unfinished view copied payload data instead of borrowing pending owner")
	}
	update.unfinished[0].pid = 999
	if pending.pid == 999 {
		t.Fatal("unfinished view scalar mutation changed pending state")
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
	if state.lifecycle.tasks[100].LastAction == "mutated outside state" {
		t.Fatal("lifecycle task update aliases TraceState task map")
	}
}

func TestTraceStateReusesUnfinishedViewStorageAfterRelease(t *testing.T) {
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

	second := first
	second.tid = 102
	second.sysID = syscallIDByName(t, "getpid")
	second.enterTime = 20
	firstUpdate := state.handleEnvelope(second)
	if len(firstUpdate.unfinished) != 1 {
		t.Fatalf("first unfinished candidates = %d, want one", len(firstUpdate.unfinished))
	}
	owner := &firstUpdate.unfinished[0]
	state.markUnfinishedPrinted(102)
	state.requeueUnfinished(101)
	state.releaseTraceStateUpdate(firstUpdate)

	third := second
	third.tid = 103
	third.enterTime = 30
	secondUpdate := state.handleEnvelope(third)
	if len(secondUpdate.unfinished) != 1 {
		t.Fatalf("second unfinished candidates = %d, want one", len(secondUpdate.unfinished))
	}
	if &secondUpdate.unfinished[0] != owner {
		t.Fatal("unfinished view storage was not reused after release")
	}
	state.releaseTraceStateUpdate(secondUpdate)
	if len(state.unfinished.reusable) != 0 || cap(state.unfinished.reusable) == 0 {
		t.Fatalf("reusable unfinished storage = len:%d cap:%d, want empty reusable backing", len(state.unfinished.reusable), cap(state.unfinished.reusable))
	}
	cleared := state.unfinished.reusable[:1]
	if cleared[0].payloadSections != nil {
		t.Fatal("reusable unfinished view retained borrowed payload section header")
	}
	state.unfinished.reusable = state.unfinished.reusable[:0]
}

func TestTraceSessionConfiguresUnfinishedIndexFromOutputMode(t *testing.T) {
	textSession := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatText}, traceSessionDeps{})
	textState, ok := textSession.dependencies.State.(*TraceState)
	if !ok || !textState.unfinished.enabled {
		t.Fatalf("text unfinished state = %#v, want enabled", textSession.dependencies.State)
	}

	jsonSession := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{})
	jsonState, ok := jsonSession.dependencies.State.(*TraceState)
	if !ok || jsonState.unfinished.enabled {
		t.Fatalf("JSON unfinished state = %#v, want disabled", jsonSession.dependencies.State)
	}

	debugSession := newTestTraceSessionWithOptions(&cli.Options{DebugEvents: true}, traceSessionDeps{})
	debugState, ok := debugSession.dependencies.State.(*TraceState)
	if !ok || debugState.unfinished.enabled {
		t.Fatalf("debug unfinished state = %#v, want disabled", debugSession.dependencies.State)
	}
}
