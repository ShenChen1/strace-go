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
	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		outWriter: &output,
	}

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
	if got := len(session.traceState().pendingSyscalls); got != 1 {
		t.Fatalf("pendingSyscalls after enter = %d, want 1", got)
	}
	session.handleEnvelope(exit)
	if got := len(session.traceState().pendingSyscalls); got != 0 {
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
	ownedData := owned.payloadSections[0].Data

	exit := enter
	exit.eventType = bpfEventTypeExit
	update := state.handleEnvelope(exit)
	if update.pendingEnter != owned {
		t.Fatal("exit copied pending state instead of transferring the deleted map entry")
	}
	if &update.pendingEnter.payloadSections[0].Data[0] != &ownedData[0] {
		t.Fatal("exit copied owned payload data during pending transfer")
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
