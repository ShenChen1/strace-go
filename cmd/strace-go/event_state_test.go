package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestJSONEventsArePairedByTIDState(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "-e", "trace=getpid", "/bin/true"})
	var output bytes.Buffer
	state := newTraceState()
	session := newTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 1234,
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
		OutWriter: &output,
		State:     state,
	})

	enter := traceEventEnvelope{
		valid:        true,
		pid:          1234,
		tid:          1234,
		sysID:        39, // getpid
		eventVersion: 2,
		eventType:    bpfEventTypeEnter,
		eventFlags:   bpfEventFlagGenericEnter,
		enterTime:    100,
	}
	exit := traceEventEnvelope{
		valid:        true,
		pid:          1234,
		tid:          1234,
		sysID:        39, // getpid
		eventVersion: 2,
		eventType:    bpfEventTypeExit,
		enterTime:    100,
		duration:     20,
		ret:          1234,
	}

	session.handleEnvelope(enter)
	if got := len(state.pendingSyscalls); got != 1 {
		t.Fatalf("pendingSyscalls after enter = %d, want 1", got)
	}
	session.handleEnvelope(exit)
	if got := len(state.pendingSyscalls); got != 0 {
		t.Fatalf("pendingSyscalls after exit = %d, want 0", got)
	}

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("JSON lines = %d, want enter and exit lines; output=%q", len(lines), output.String())
	}
	var exitEvent struct {
		EventType   string `json:"event_type"`
		PairedEnter bool   `json:"paired_enter"`
	}
	if err := json.Unmarshal(lines[1], &exitEvent); err != nil {
		t.Fatalf("decode exit JSON: %v", err)
	}
	if exitEvent.EventType != "exit" || !exitEvent.PairedEnter {
		t.Fatalf("exit JSON = %+v, want event_type=exit paired_enter=true", exitEvent)
	}
}

func TestTraceStatePendingStaleCountTracksUnconsumedEnters(t *testing.T) {
	state := newTraceState()
	enter := traceEventEnvelope{
		valid:      true,
		pid:        1234,
		tid:        1235,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	}
	exit := enter
	exit.eventType = bpfEventTypeExit

	if got := state.PendingStaleCount(); got != 0 {
		t.Fatalf("initial pending stale count = %d, want zero", got)
	}
	state.handleEnvelope(enter)
	if got := state.PendingStaleCount(); got != 1 {
		t.Fatalf("pending stale count after enter = %d, want one", got)
	}
	state.handleEnvelope(exit)
	if got := state.PendingStaleCount(); got != 0 {
		t.Fatalf("pending stale count after paired exit = %d, want zero", got)
	}
}

func TestTraceStateHandlePairsEnterExitAndCleansLifecycle(t *testing.T) {
	state := newTraceState()
	enter := traceEventEnvelope{
		valid:      true,
		pid:        1234,
		tid:        1235,
		sysID:      39,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  100,
	}
	exit := traceEventEnvelope{
		valid:     true,
		pid:       1234,
		tid:       1235,
		sysID:     39,
		eventType: bpfEventTypeExit,
	}

	enterUpdate := state.handleEnvelope(enter)
	if enterUpdate.kind != traceStateSyscallEnter || len(state.pendingSyscalls) != 1 {
		t.Fatalf("enter update = %+v pending=%d, want enter with one pending", enterUpdate, len(state.pendingSyscalls))
	}
	exitUpdate := state.handleEnvelope(exit)
	if exitUpdate.kind != traceStateSyscallExit || exitUpdate.pendingEnter == nil || len(state.pendingSyscalls) != 0 {
		t.Fatalf("exit update = %+v pending=%d, want paired exit with no pending", exitUpdate, len(state.pendingSyscalls))
	}

	state.rememberPendingExecArgs(1235, "execve(...)")
	state.rememberSuspendedSyscall(1235, "nanosleep")
	lifecycleUpdate := state.handleEnvelope(traceEventEnvelope{
		valid:           true,
		pid:             1234,
		tid:             1235,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFree,
	})
	if lifecycleUpdate.kind != traceStateLifecycle || lifecycleUpdate.lifecycleView.action != lifecycleFree {
		t.Fatalf("lifecycle update = %+v, want lifecycle free view", lifecycleUpdate)
	}
	if len(state.pendingExecArgs) != 0 || len(state.suspendedSyscalls) != 0 || len(state.pendingSyscalls) != 0 {
		t.Fatalf("lifecycle free did not clear pending state: %+v", state)
	}
}

func TestTraceStateExitWithoutEnterStillEnsuresTaskState(t *testing.T) {
	state := newTraceState()
	state.handleEnvelope(traceEventEnvelope{
		valid:     true,
		pid:       1234,
		tid:       1235,
		sysID:     39,
		eventType: bpfEventTypeExit,
		enterTime: 80,
	})

	task := state.tasks[1235]
	if task == nil || !task.Alive || task.LastSeenNS != 80 {
		t.Fatalf("exit-only task state = %+v, want alive task at timestamp 80", task)
	}
}

func TestTraceStateRecyclesMismatchedPendingExit(t *testing.T) {
	state := newTraceState()
	enterID := syscallIDByName(t, "getpid")
	exitID := syscallIDByName(t, "getppid")
	state.handleEnvelope(traceEventEnvelope{
		valid:      true,
		pid:        1234,
		tid:        1235,
		sysID:      enterID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})
	pending := state.pendingSyscalls[1235]
	if pending == nil {
		t.Fatal("enter did not create pending syscall")
	}

	update := state.handleEnvelope(traceEventEnvelope{
		valid:     true,
		pid:       1234,
		tid:       1235,
		sysID:     exitID,
		eventType: bpfEventTypeExit,
	})
	if update.pendingEnter != nil {
		t.Fatalf("mismatched exit paired with pending state: %+v", update.pendingEnter)
	}
	if len(state.pendingSyscalls) != 0 {
		t.Fatalf("pending syscalls = %d, want zero after mismatch", len(state.pendingSyscalls))
	}
	if len(state.reusablePending) != 1 || state.reusablePending[0] != pending {
		t.Fatalf("reusable pending = %p, want mismatched object %p", state.reusablePending, pending)
	}
}

func TestTraceStateReordersExitObservedBeforeEnter(t *testing.T) {
	state := newTraceStateWithDeferredExit(true)
	sysID := syscallIDByName(t, "creat")
	path := []byte("late-enter.txt\x00")
	exit := traceEventEnvelope{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     sysID,
		eventType: bpfEventTypeExit,
		enterTime: 100,
		ret:       -21,
	}
	deferred := state.handleEnvelope(exit)
	if !deferred.deferred || len(state.pendingExits) != 1 {
		t.Fatalf("exit update = %+v pending exits = %d, want deferred exit", deferred, len(state.pendingExits))
	}

	enter := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      sysID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  100,
		args:       [6]uint64{0x1000, 0644},
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindString,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1000,
			Data:      path,
		}},
	}
	update := state.handleEnvelope(enter)
	if update.deferredExit == nil || update.deferredExit.pendingEnter == nil {
		t.Fatalf("enter update = %+v, want deferred exit paired with enter", update)
	}
	if len(update.deferredExit.pendingEnter.payloadSections) != 1 ||
		string(update.deferredExit.pendingEnter.payloadSections[0].Data) != string(path) {
		t.Fatalf("reordered payload = %+v, want path snapshot", update.deferredExit.pendingEnter.payloadSections)
	}
	if len(state.pendingSyscalls) != 0 || len(state.pendingExits) != 0 {
		t.Fatalf("state after reordered pair = %+v, want no pending syscall or exit", state)
	}
}

func TestTraceStateClearsDeferredExitOnLifecycleFree(t *testing.T) {
	state := newTraceStateWithDeferredExit(true)
	exit := traceEventEnvelope{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     syscallIDByName(t, "creat"),
		eventType: bpfEventTypeExit,
		enterTime: 100,
	}
	state.handleEnvelope(exit)
	if len(state.pendingExits) != 1 {
		t.Fatalf("pending exits = %d, want one before lifecycle cleanup", len(state.pendingExits))
	}

	update := state.handleEnvelope(traceEventEnvelope{
		valid:           true,
		pid:             101,
		tid:             101,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFree,
	})
	if update.deferredExit == nil || update.deferredExit.syscallView.sysID != exit.sysID {
		t.Fatalf("lifecycle update = %+v, want deferred unpaired exit", update)
	}
	if len(state.pendingExits) != 0 {
		t.Fatalf("pending exits = %d, want zero after lifecycle free", len(state.pendingExits))
	}
}

func TestTraceStateHandleEnvelopeUsesSyscallViewForPendingPair(t *testing.T) {
	state := newTraceState()
	envelopeBase := traceEventEnvelope{
		valid:      true,
		pid:        1,
		tid:        1,
		sysID:      39,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  100,
	}
	viewEnter := envelopeBase
	viewEnter.pid = 200
	viewEnter.tid = 201
	viewEnter.sysID = 60
	viewEnter.args = [6]uint64{7}

	enterUpdate := state.handleEnvelope(viewEnter)
	if enterUpdate.kind != traceStateSyscallEnter {
		t.Fatalf("enter update = %+v, want syscall enter", enterUpdate)
	}
	if enterUpdate.syscallView.tid != 201 || enterUpdate.syscallView.sysID != 60 || enterUpdate.syscallView.args[0] != 7 {
		t.Fatalf("enter syscall view = %+v, want view tid/sysid/args", enterUpdate.syscallView)
	}
	if _, ok := state.pendingSyscalls[201]; !ok {
		t.Fatal("pending syscall missing under view tid 201")
	}
	if _, ok := state.pendingSyscalls[1]; ok {
		t.Fatal("pending syscall unexpectedly stored under base envelope tid 1")
	}

	viewExit := envelopeBase
	viewExit.pid = 200
	viewExit.tid = 201
	viewExit.sysID = 60
	viewExit.eventType = bpfEventTypeExit

	exitUpdate := state.handleEnvelope(viewExit)
	if exitUpdate.pendingEnter == nil || exitUpdate.pendingEnter.pid != 200 || exitUpdate.pendingEnter.sysID != 60 {
		t.Fatalf("paired enter = %+v, want view pid/sysid", exitUpdate.pendingEnter)
	}
	if exitUpdate.syscallView.tid != 201 || exitUpdate.syscallView.sysID != 60 {
		t.Fatalf("exit syscall view = %+v, want paired view tid/sysid", exitUpdate.syscallView)
	}
}
