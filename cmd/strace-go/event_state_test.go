package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func TestJSONEventsArePairedByTIDState(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "-e", "trace=getpid", "/bin/true"})
	var output bytes.Buffer
	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
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

	enterUpdate := state.Handle(enter)
	if enterUpdate.kind != traceStateSyscallEnter || len(state.pendingSyscalls) != 1 {
		t.Fatalf("enter update = %+v pending=%d, want enter with one pending", enterUpdate, len(state.pendingSyscalls))
	}
	exitUpdate := state.Handle(exit)
	if exitUpdate.kind != traceStateSyscallExit || exitUpdate.pendingEnter == nil || len(state.pendingSyscalls) != 0 {
		t.Fatalf("exit update = %+v pending=%d, want paired exit with no pending", exitUpdate, len(state.pendingSyscalls))
	}

	state.rememberPendingExecArgs(1235, "execve(...)")
	state.rememberSuspendedSyscall(1235, "nanosleep")
	state.Handle(&bpfEvent{
		Pid:        1234,
		Tid:        1235,
		EventType:  bpfEventTypeLifecycle,
		EventFlags: lifecycleFree,
	})
	if len(state.pendingExecArgs) != 0 || len(state.suspendedSyscalls) != 0 || len(state.pendingSyscalls) != 0 {
		t.Fatalf("lifecycle free did not clear pending state: %+v", state)
	}
}

func TestZeroEventTypeIsNotExit(t *testing.T) {
	eventRaw := &bpfEvent{EventVersion: 2}

	if isExitEvent(eventRaw) {
		t.Fatal("event_type=0 should not be treated as an explicit exit event")
	}
	if got := bpfEventTypeName(eventRaw); got != "unknown" {
		t.Fatalf("bpfEventTypeName(event_type=0) = %q, want unknown", got)
	}
}
