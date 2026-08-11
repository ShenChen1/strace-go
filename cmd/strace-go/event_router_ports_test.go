package main

import "testing"

type recordingLifecycleSink struct {
	inherits [][2]int
	handled  int
}

func (s *recordingLifecycleSink) Handle(lifecycleEventView, *TaskState) {
	s.handled++
}

func (s *recordingLifecycleSink) InheritProcessState(parentPID int, childPID int) {
	s.inherits = append(s.inherits, [2]int{parentPID, childPID})
}

type recordingEnterSink struct {
	handled int
}

func (s *recordingEnterSink) HandleEnter(syscallEventContext) {
	s.handled++
}

type recordingExitSink struct {
	exits      int
	unfinished int
}

func (s *recordingExitSink) Handle(syscallEventContext) {
	s.exits++
}

func (s *recordingExitSink) HandleUnfinished(syscallEventContext) bool {
	s.unfinished++
	return true
}

func TestTraceEventRouterDispatchesThroughOutputPorts(t *testing.T) {
	lifecycle := &recordingLifecycleSink{}
	enter := &recordingEnterSink{}
	exit := &recordingExitSink{}
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, nil),
		TargetPID: 100,
		State:     newTraceState(),
		Lifecycle: lifecycle,
		JSON:      enter,
		Pipeline:  exit,
	})

	router.Handle(traceEventEnvelope{
		valid:           true,
		pid:             100,
		tid:             100,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleExec,
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})
	router.Handle(traceEventEnvelope{
		valid:     true,
		pid:       100,
		tid:       100,
		sysID:     syscallIDByName(t, "getpid"),
		eventType: bpfEventTypeExit,
		ret:       100,
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if lifecycle.handled != 1 || enter.handled != 3 || exit.exits != 1 || exit.unfinished != 1 {
		t.Fatalf("dispatch counts = lifecycle %d enter %d exit %d unfinished %d, want 1/3/1/1", lifecycle.handled, enter.handled, exit.exits, exit.unfinished)
	}
}

var (
	_ lifecycleEventSink = (*recordingLifecycleSink)(nil)
	_ syscallEnterSink   = (*recordingEnterSink)(nil)
	_ syscallExitSink    = (*recordingExitSink)(nil)
)
