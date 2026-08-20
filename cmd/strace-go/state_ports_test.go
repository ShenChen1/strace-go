package main

import (
	"path/filepath"
	"strings"
	"testing"
)

type recordingTraceEventState struct {
	calls        int
	releaseCalls int
	update       TraceStateUpdate
}

func (s *recordingTraceEventState) handleEnvelope(traceEventEnvelope) TraceStateUpdate {
	s.calls++
	return s.update
}

func (s *recordingTraceEventState) releaseTraceStateUpdate(TraceStateUpdate) {
	s.releaseCalls++
}

func (*recordingTraceEventState) markUnfinishedPrinted(uint32) {}

func (*recordingTraceEventState) requeueUnfinished(uint32) {}

func (*recordingTraceEventState) setUnfinishedEnabled(bool) {}

func TestTraceEventRouterUsesEventStatePort(t *testing.T) {
	state := &recordingTraceEventState{
		update: TraceStateUpdate{kind: traceStateSyscallFragment},
	}
	router := newTestTraceEventRouter(traceEventRouterTestDeps{
		Scope: newTraceScope(100, nil),
		State: state,
	})

	router.Handle(traceEventEnvelope{valid: true, pid: 100, tid: 100})

	if state.calls != 1 {
		t.Fatalf("state calls = %d, want one event-state call", state.calls)
	}
	if state.releaseCalls != 1 {
		t.Fatalf("state release calls = %d, want one release on fragment early return", state.releaseCalls)
	}
}

func TestTraceEventRouterDoesNotBuildDefaultStatePort(t *testing.T) {
	router := newTestTraceEventRouter(traceEventRouterTestDeps{
		Scope: newTraceScope(100, nil),
	})
	if router == nil {
		t.Fatal("router should remain available as an inert boundary")
	}
	if router.state != nil {
		t.Fatal("router unexpectedly created a default event-state port")
	}

	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if router.state != nil {
		t.Fatal("router Handle unexpectedly created an event-state port")
	}
}

func TestTraceEventRouterDoesNotOwnStateConstruction(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/event_router.go"))
	if strings.Contains(source, "newTraceState()") {
		t.Fatal("event router must not construct TraceState")
	}
}

var (
	_ traceEventState       = (*recordingTraceEventState)(nil)
	_ textRendererState     = (*TraceState)(nil)
	_ execSyscallState      = (*TraceState)(nil)
	_ suspendedSyscallState = (*TraceState)(nil)
)
