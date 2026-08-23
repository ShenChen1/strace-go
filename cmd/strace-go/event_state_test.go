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
	if got := len(state.correlation.pendingSyscalls); got != 1 {
		t.Fatalf("pendingSyscalls after enter = %d, want 1", got)
	}
	session.handleEnvelope(exit)
	if got := len(state.correlation.pendingSyscalls); got != 0 {
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
	if enterUpdate.kind != traceStateSyscallEnter || len(state.correlation.pendingSyscalls) != 1 {
		t.Fatalf("enter update = %+v pending=%d, want enter with one pending", enterUpdate, len(state.correlation.pendingSyscalls))
	}
	exitUpdate := state.handleEnvelope(exit)
	if exitUpdate.kind != traceStateSyscallExit || exitUpdate.pendingEnter == nil || len(state.correlation.pendingSyscalls) != 0 {
		t.Fatalf("exit update = %+v pending=%d, want paired exit with no pending", exitUpdate, len(state.correlation.pendingSyscalls))
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
	if len(state.correlation.pendingExecArgs) != 0 || len(state.correlation.suspendedSyscalls) != 0 || len(state.correlation.pendingSyscalls) != 0 {
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

	task := state.lifecycle.tasks[1235]
	if task == nil || !task.Alive || task.LastSeenNS != 80 {
		t.Fatalf("exit-only task state = %+v, want alive task at timestamp 80", task)
	}
}

func TestTraceStateSynthesizesElidedPlainEnter(t *testing.T) {
	for _, format := range []string{cli.EventFormatText, cli.EventFormatJSON, cli.EventFormatHandler} {
		t.Run(format, func(t *testing.T) {
			policy := newTraceEventPolicy(&cli.Options{EventFormat: format})
			state := newTraceStateForSession(policy)
			exit := traceEventEnvelope{
				valid:     true,
				pid:       1234,
				tid:       1235,
				sysID:     syscallIDByName(t, "getpid"),
				eventType: bpfEventTypeExit,
				args:      [6]uint64{7, 8},
				enterTime: 80,
				duration:  20,
				ret:       1234,
			}
			update := state.handleEnvelope(exit)
			if update.deferred || update.pendingEnter == nil || !update.pendingEnter.genericEnterRaw {
				t.Fatalf("elided plain exit update = %+v, want synthetic paired enter", update)
			}
			if got := update.pendingEnter.args; got != exit.args {
				t.Fatalf("synthetic args = %#v, want %#v", got, exit.args)
			}
			if len(state.lifecycle.tasks) != 0 {
				t.Fatalf("synthetic plain exit created syscall task state: %+v", state.lifecycle.tasks)
			}
			state.releaseTraceStateUpdate(update)
		})
	}
}

func TestTraceStateSynthesizesTextStandaloneTimeExit(t *testing.T) {
	textState := newTraceStateForSession(newTraceEventPolicy(cli.ParseArgs([]string{"/bin/true"})))
	textExit := traceEventEnvelope{
		valid:     true,
		pid:       1234,
		tid:       1235,
		sysID:     syscallIDByName(t, "clock_gettime"),
		eventType: bpfEventTypeExit,
		args:      [6]uint64{1, 0x2000},
		enterTime: 80,
		duration:  20,
		ret:       0,
	}
	update := textState.handleEnvelope(textExit)
	if update.deferred || update.pendingEnter == nil || !update.pendingEnter.genericEnterRaw {
		t.Fatalf("text standalone time exit update = %+v, want synthetic paired enter", update)
	}
	if update.pendingEnter.args != textExit.args {
		t.Fatalf("synthetic time args = %#v, want %#v", update.pendingEnter.args, textExit.args)
	}
	textState.releaseTraceStateUpdate(update)

	jsonState := newTraceStateForSession(newTraceEventPolicy(&cli.Options{EventFormat: cli.EventFormatJSON}))
	deferred := jsonState.handleEnvelope(textExit)
	if !deferred.deferred || deferred.pendingEnter != nil || len(jsonState.correlation.pendingExits) != 1 {
		t.Fatalf("JSON standalone time exit update = %+v pending=%d, want conservative defer", deferred, len(jsonState.correlation.pendingExits))
	}
}

func TestTraceStateSynthesizesTextStandaloneSmallStructExit(t *testing.T) {
	for _, name := range []string{"arch_prctl", "get_robust_list"} {
		t.Run(name, func(t *testing.T) {
			state := newTraceStateForSession(newTraceEventPolicy(cli.ParseArgs([]string{"/bin/true"})))
			args := [6]uint64{0, 0x2000, 0x3000}
			if name == "arch_prctl" {
				args[0] = 0x1003
			}
			update := state.handleEnvelope(traceEventEnvelope{
				valid:     true,
				pid:       1234,
				tid:       1235,
				sysID:     syscallIDByName(t, name),
				eventType: bpfEventTypeExit,
				args:      args,
				enterTime: 80,
				ret:       0,
			})
			if update.deferred || update.pendingEnter == nil || !update.pendingEnter.genericEnterRaw {
				t.Fatalf("%s text exit update = %+v, want synthetic paired enter", name, update)
			}
			state.releaseTraceStateUpdate(update)
		})
	}
}

func TestTraceStateKeepsSpecialEnterExitDeferred(t *testing.T) {
	policy := newTraceEventPolicy(&cli.Options{EventFormat: cli.EventFormatJSON})
	state := newTraceStateForSession(policy)
	exit := traceEventEnvelope{
		valid:     true,
		pid:       1234,
		tid:       1235,
		sysID:     syscallIDByName(t, "openat"),
		eventType: bpfEventTypeExit,
		enterTime: 80,
		ret:       -2,
	}
	update := state.handleEnvelope(exit)
	if !update.deferred || update.pendingEnter != nil || len(state.correlation.pendingExits) != 1 {
		t.Fatalf("special route exit update = %+v pending=%d, want deferred", update, len(state.correlation.pendingExits))
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
	pending := state.correlation.pendingSyscalls[1235]
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
	if len(state.correlation.pendingSyscalls) != 0 {
		t.Fatalf("pending syscalls = %d, want zero after mismatch", len(state.correlation.pendingSyscalls))
	}
	if len(state.correlation.reusablePending) != 1 || state.correlation.reusablePending[0] != pending {
		t.Fatalf("reusable pending = %p, want mismatched object %p", state.correlation.reusablePending, pending)
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
	if !deferred.deferred || len(state.correlation.pendingExits) != 1 {
		t.Fatalf("exit update = %+v pending exits = %d, want deferred exit", deferred, len(state.correlation.pendingExits))
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
	if !update.deferredExit.valid || update.deferredExit.pendingEnter == nil {
		t.Fatalf("enter update = %+v, want deferred exit paired with enter", update)
	}
	if len(update.deferredExit.pendingEnter.payloadSections) != 1 ||
		string(update.deferredExit.pendingEnter.payloadSections[0].Data) != string(path) {
		t.Fatalf("reordered payload = %+v, want path snapshot", update.deferredExit.pendingEnter.payloadSections)
	}
	if len(state.correlation.pendingSyscalls) != 0 || len(state.correlation.pendingExits) != 0 {
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
	if len(state.correlation.pendingExits) != 1 {
		t.Fatalf("pending exits = %d, want one before lifecycle cleanup", len(state.correlation.pendingExits))
	}

	update := state.handleEnvelope(traceEventEnvelope{
		valid:           true,
		pid:             101,
		tid:             101,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFree,
	})
	if !update.deferredExit.valid || update.deferredExit.syscallView.sysID != exit.sysID {
		t.Fatalf("lifecycle update = %+v, want deferred unpaired exit", update)
	}
	if len(state.correlation.pendingExits) != 0 {
		t.Fatalf("pending exits = %d, want zero after lifecycle free", len(state.correlation.pendingExits))
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
	if _, ok := state.correlation.pendingSyscalls[201]; !ok {
		t.Fatal("pending syscall missing under view tid 201")
	}
	if _, ok := state.correlation.pendingSyscalls[1]; ok {
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
