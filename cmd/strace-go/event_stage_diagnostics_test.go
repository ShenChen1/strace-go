package main

import (
	"testing"
	"time"
)

func TestTraceEventStageDiagnosticsRecordsSampledStages(t *testing.T) {
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{100, 130, 170},
	}
	diagnostics := newTraceEventStageDiagnostics(true, clock, 1)
	sample := diagnostics.begin()
	stateEnd := diagnostics.now(sample)
	diagnostics.recordState(sample, stateEnd)
	diagnostics.recordDispatch(sample, stateEnd, diagnostics.now(sample))

	stats := diagnostics.EventStageStats()
	if !stats.Enabled || stats.SampleRate != 1 || stats.StateRecords != 1 ||
		stats.StateTimeNS != 30 || stats.MaxStateTimeNS != 30 ||
		stats.DispatchRecords != 1 || stats.DispatchTimeNS != 40 || stats.MaxDispatchTimeNS != 40 {
		t.Fatalf("stage stats = %+v, want sampled state=30 dispatch=40", stats)
	}
}

func TestTraceEventStageDiagnosticsSamplesAtConfiguredRate(t *testing.T) {
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{100, 130, 170, 200, 240, 280},
	}
	diagnostics := newTraceEventStageDiagnostics(true, clock, 2)
	for index := 0; index < 3; index++ {
		sample := diagnostics.begin()
		if !sample.valid {
			continue
		}
		stateEnd := diagnostics.now(sample)
		diagnostics.recordState(sample, stateEnd)
		diagnostics.recordDispatch(sample, stateEnd, diagnostics.now(sample))
	}

	stats := diagnostics.EventStageStats()
	if stats.StateRecords != 2 || stats.DispatchRecords != 2 || stats.StateTimeNS != 70 || stats.DispatchTimeNS != 80 {
		t.Fatalf("sampled stage stats = %+v, want two samples", stats)
	}
}

func TestTraceEventStageDiagnosticsDisabledDoesNotReadClock(t *testing.T) {
	clock := &diagnosticTraceClock{now: time.Unix(100, 0), monoNS: []uint64{100, 130}}
	if diagnostics := newTraceEventStageDiagnostics(false, clock, 1); diagnostics != nil {
		t.Fatal("disabled stage diagnostics allocated a hot-path timer")
	}
	if clock.monoCall != 0 {
		t.Fatalf("disabled diagnostics clock calls = %d, want 0", clock.monoCall)
	}
}

func TestTraceEventRouterPublishesStageStats(t *testing.T) {
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{100, 130, 170},
	}
	router := newTestTraceEventRouter(traceEventRouterTestDeps{
		Scope:            newTraceScope(100, nil),
		TargetPID:        100,
		State:            newTraceState(),
		StageDiagnostics: newTraceEventStageDiagnostics(true, clock, 1),
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	stats := router.EventStageStats()
	if stats.StateRecords != 1 || stats.DispatchRecords != 1 || stats.StateTimeNS != 30 || stats.DispatchTimeNS != 40 {
		t.Fatalf("router stage stats = %+v, want state=30 dispatch=40", stats)
	}
}
