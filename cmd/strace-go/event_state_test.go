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

	enter := &bpfEvent{
		Pid:          1234,
		Tid:          1234,
		SysId:        39, // getpid
		EventVersion: 2,
		EventType:    bpfEventTypeEnter,
		EventFlags:   bpfEventFlagGenericEnter,
		EnterTime:    100,
	}
	exit := &bpfEvent{
		Pid:          1234,
		Tid:          1234,
		SysId:        39, // getpid
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
		EnterTime:    100,
		Duration:     20,
		Ret:          1234,
	}

	session.handleEvent(enter)
	if got := len(session.traceState().pendingSyscalls); got != 1 {
		t.Fatalf("pendingSyscalls after enter = %d, want 1", got)
	}
	session.handleEvent(exit)
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
	enter := &bpfEvent{
		Pid:        1234,
		Tid:        1235,
		SysId:      39,
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagGenericEnter,
		EnterTime:  100,
	}
	exit := &bpfEvent{
		Pid:       1234,
		Tid:       1235,
		SysId:     39,
		EventType: bpfEventTypeExit,
	}

	enterUpdate := state.handleEnvelope(newTraceEventEnvelopeFromBPF(enter))
	if enterUpdate.kind != traceStateSyscallEnter || len(state.pendingSyscalls) != 1 {
		t.Fatalf("enter update = %+v pending=%d, want enter with one pending", enterUpdate, len(state.pendingSyscalls))
	}
	exitUpdate := state.handleEnvelope(newTraceEventEnvelopeFromBPF(exit))
	if exitUpdate.kind != traceStateSyscallExit || exitUpdate.pendingEnter == nil || len(state.pendingSyscalls) != 0 {
		t.Fatalf("exit update = %+v pending=%d, want paired exit with no pending", exitUpdate, len(state.pendingSyscalls))
	}

	state.rememberPendingExecArgs(1235, "execve(...)")
	state.rememberSuspendedSyscall(1235, "nanosleep")
	lifecycleUpdate := state.handleEnvelope(newTraceEventEnvelopeFromBPF(&bpfEvent{
		Pid:             1234,
		Tid:             1235,
		EventType:       bpfEventTypeLifecycle,
		LifecycleAction: lifecycleFree,
	}))
	if lifecycleUpdate.kind != traceStateLifecycle || lifecycleUpdate.lifecycleView.action != lifecycleFree {
		t.Fatalf("lifecycle update = %+v, want lifecycle free view", lifecycleUpdate)
	}
	if len(state.pendingExecArgs) != 0 || len(state.suspendedSyscalls) != 0 || len(state.pendingSyscalls) != 0 {
		t.Fatalf("lifecycle free did not clear pending state: %+v", state)
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
			Data:     []byte("typed.txt\x00"),
		}},
	}

	update := state.handleEnvelope(envelope)

	if update.kind != traceStateSyscallEnter {
		t.Fatalf("update kind = %d, want enter", update.kind)
	}
	if len(update.payloadSections) != 1 || string(update.payloadSections[0].Data) != "typed.txt\x00" {
		t.Fatalf("enter update payload sections = %+v, want semantic path section", update.payloadSections)
	}
	if len(state.pendingSyscalls[101].payloadSections) != 1 {
		t.Fatalf("pending payload sections = %+v, want cached enter payload", state.pendingSyscalls[101].payloadSections)
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

func TestZeroEventTypeIsNotExit(t *testing.T) {
	eventRaw := &bpfEvent{EventVersion: 2}

	if newTraceEventEnvelopeFromBPF(eventRaw).isExit() {
		t.Fatal("event_type=0 should not be treated as an explicit exit event")
	}
	if got := bpfEventTypeNameFromID(eventRaw.EventType); got != "unknown" {
		t.Fatalf("bpfEventTypeNameFromID(event_type=0) = %q, want unknown", got)
	}
}
