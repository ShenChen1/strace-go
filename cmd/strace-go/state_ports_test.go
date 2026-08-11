package main

import "testing"

type recordingTraceEventState struct {
	calls  int
	update TraceStateUpdate
}

func (s *recordingTraceEventState) handleEnvelope(traceEventEnvelope) TraceStateUpdate {
	s.calls++
	return s.update
}

func (*recordingTraceEventState) markUnfinishedPrinted(uint32) {}

func (*recordingTraceEventState) requeueUnfinished(uint32) {}

func TestTraceEventRouterUsesEventStatePort(t *testing.T) {
	state := &recordingTraceEventState{
		update: TraceStateUpdate{kind: traceStateSyscallFragment},
	}
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope: newTraceScope(100, nil),
		State: state,
	})

	router.Handle(traceEventEnvelope{valid: true, pid: 100, tid: 100})

	if state.calls != 1 {
		t.Fatalf("state calls = %d, want one event-state call", state.calls)
	}
}

func TestTraceEventRouterBuildsDefaultStatePort(t *testing.T) {
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope: newTraceScope(100, nil),
	})

	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if router.state == nil {
		t.Fatal("router did not install a default event-state port")
	}
}

var (
	_ traceEventState       = (*recordingTraceEventState)(nil)
	_ textRendererState     = (*TraceState)(nil)
	_ execSyscallState      = (*TraceState)(nil)
	_ suspendedSyscallState = (*TraceState)(nil)
)
