package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestIntegrityGapInvalidatesHistoryBeforeCurrentEvent(t *testing.T) {
	state := &TraceState{}
	fd := newFDStateStore(map[string]string{"10:3": "/old", "10:cwd": "/old-cwd", "20:3": "/shared"})
	integrity := newTraceIntegrity(traceIntegrityDeps{State: state, FDState: fd})
	first := traceEventEnvelope{valid: true, pid: 10, tid: 11, eventType: bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter, seq: 1}
	integrity.Observe(&first)
	state.handleEnvelope(first)
	if state.PendingStaleCount() != 1 {
		t.Fatal("happy path did not remember enter")
	}
	next := first
	next.seq = 3
	next.lossEpoch = 1
	next.eventType = bpfEventTypeExit
	next.eventFlags = 0
	integrity.Observe(&next)
	update := state.handleEnvelope(next)
	defer state.releaseTraceStateUpdate(update)
	if update.pendingEnter != nil || state.PendingStaleCount() != 0 || !next.tainted {
		t.Fatal("gap reused pending enter or failed to mark the current record")
	}
	for _, pid := range []int{10, 20} {
		if path, ok := fd.Path(pid, 3); ok {
			t.Fatalf("gap retained historical fd: %s", path)
		}
	}
	if _, ok := fd.Cwd(10); ok {
		t.Fatal("gap retained historical cwd")
	}
}

func TestIntegritySequenceDomainsAndDiscontinuities(t *testing.T) {
	cases := []struct {
		name    string
		events  []traceEventEnvelope
		tainted bool
	}{
		{"normal migration", []traceEventEnvelope{{seq: 1}, {cpu: 2, seq: 1}, {seq: 2}}, false},
		{"first expected", []traceEventEnvelope{{seq: 1}}, false},
		{"first nested producer reorder", []traceEventEnvelope{{seq: 2}, {seq: 1}, {seq: 3}}, false},
		{"first attempt lost", []traceEventEnvelope{{seq: 2, lossEpoch: 1}}, true},
		{"gap", []traceEventEnvelope{{seq: 1}, {seq: 3, lossEpoch: 1}}, true},
		{"nested producer reorder", []traceEventEnvelope{{seq: 1}, {seq: 3}, {seq: 2}, {seq: 4}}, false},
		{"duplicate", []traceEventEnvelope{{seq: 1}, {seq: 1}}, true},
		{"backwards", []traceEventEnvelope{{seq: 1}, {seq: 0}}, true},
		{"other cpu reports loss", []traceEventEnvelope{{seq: 1}, {cpu: 2, seq: 1, lossEpoch: 1}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			integrity := newTraceIntegrity(traceIntegrityDeps{})
			for _, ev := range tc.events {
				integrity.Observe(&ev)
			}
			if integrity.Snapshot().Tainted != tc.tainted {
				t.Fatalf("integrity = %+v", integrity.Snapshot())
			}
		})
	}
}

func TestIntegrityReorderedRecordDoesNotMoveHighWaterBackwards(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	for _, seq := range []uint64{1, 3, 2, 4} {
		ev := traceEventEnvelope{seq: seq}
		i.Observe(&ev)
	}
	s := i.Snapshot()
	if s.Tainted || s.StreamGaps != 0 || s.EstimatedLost != 0 || s.SequenceReorders != 1 {
		t.Fatalf("nested producer reorder degraded integrity: %+v", s)
	}
}

func TestIntegrityFirstDroppedAttemptIsCounted(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	ev := traceEventEnvelope{pid: 10, tid: 11, seq: 2, lossEpoch: 1}
	i.Observe(&ev)

	s := i.Snapshot()
	if !s.Tainted || s.StreamGaps != 1 || s.EstimatedLost != 1 ||
		s.ExpectedSequence != 1 || s.ObservedSequence != 2 {
		t.Fatalf("first dropped attempt = %+v, want one session gap from seq 1", s)
	}
}

func TestIntegrityGapUsesRecordTimestamp(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	first := traceEventEnvelope{seq: 1, recordTime: 100, enterTime: 100}
	i.Observe(&first)
	next := traceEventEnvelope{seq: 3, lossEpoch: 1, recordTime: 1000, enterTime: 945}
	i.Observe(&next)

	if got := i.Snapshot().TimestampNS; got != 1000 {
		t.Fatalf("gap timestamp = %d, want record timestamp 1000", got)
	}
}

func TestIntegrityUnresolvedGapFailsClosedAtObservedEnd(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	for _, seq := range []uint64{1, 3} {
		ev := traceEventEnvelope{seq: seq}
		i.Observe(&ev)
	}
	if i.Snapshot().Tainted {
		t.Fatal("unresolved jump was confirmed before a reorder could arrive")
	}

	i.Finalize(bpfRuntimeStats{Available: true, EventSequences: []uint64{3}})
	if snapshot := i.Snapshot(); !snapshot.Tainted || snapshot.Reason != "sequence_gap_at_finalization" {
		t.Fatalf("unresolved final gap = %+v, want fail-closed taint", snapshot)
	}
}

func TestIntegrityOrphanDiagnosticDoesNotTaint(t *testing.T) {
	integrity := newTraceIntegrity(traceIntegrityDeps{})
	integrity.Finalize(bpfRuntimeStats{Available: true, OrphanExit: 1})

	if snapshot := integrity.Snapshot(); snapshot.Tainted {
		t.Fatalf("orphan-only diagnostics tainted integrity: %+v", snapshot)
	}
}

func TestIntegrityInvalidRecordClearsOwnedPayloadAndDisablesCorrelation(t *testing.T) {
	state := &TraceState{deferUnmatchedExits: true}
	view := syscallEventView{valid: true, pid: 10, tid: 11, sysID: 0, eventType: bpfEventTypeEnter}
	state.correlation.rememberEnterEvent(&view, []handler.PayloadSection{{Data: []byte("old")}})
	state.correlation.rememberPendingExit(&view, nil)
	state.rememberPendingExecArgs(11, "old")
	state.rememberSuspendedSyscall(11, "read")
	integrity := newTraceIntegrity(traceIntegrityDeps{State: state})
	integrity.InvalidRecord()
	if state.PendingStaleCount() != 0 || len(state.correlation.pendingExits) != 0 ||
		len(state.correlation.pendingExecArgs) != 0 || len(state.correlation.suspendedSyscalls) != 0 {
		t.Fatal("invalid record left correlation resources alive")
	}
	enter := traceEventEnvelope{valid: true, eventType: bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter, pid: 10, tid: 11}
	state.handleEnvelope(enter)
	if state.PendingStaleCount() != 1 {
		t.Fatal("fresh enter failed to establish a recovery candidate")
	}
}
