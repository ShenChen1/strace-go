package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestIntegrityCorrelationRecoversAndSecondGapInvalidatesAgain(t *testing.T) {
	state := &TraceState{deferUnmatchedExits: true}
	i := newTraceIntegrity(traceIntegrityDeps{State: state})
	emit := func(seq, stamp, lossEpoch uint64, kind uint16) TraceStateUpdate {
		ev := traceEventEnvelope{valid: true, pid: 10, tid: 11, sysID: 1,
			seq: seq, lossEpoch: lossEpoch, enterTime: stamp, eventType: kind}
		if kind == bpfEventTypeEnter {
			ev.eventFlags = bpfEventFlagGenericEnter
		}
		i.Observe(&ev)
		return state.handleEnvelope(ev)
	}
	state.releaseTraceStateUpdate(emit(1, 100, 0, bpfEventTypeEnter))
	update := emit(3, 100, 1, bpfEventTypeExit)
	if update.pendingEnter != nil || update.deferred {
		t.Fatal("gap exit reused or deferred old correlation")
	}
	state.releaseTraceStateUpdate(update)
	state.releaseTraceStateUpdate(emit(4, 200, 1, bpfEventTypeEnter))
	update = emit(5, 200, 1, bpfEventTypeExit)
	if update.pendingEnter == nil {
		t.Fatal("fresh pair did not recover correlation")
	}
	state.releaseTraceStateUpdate(update)
	state.releaseTraceStateUpdate(emit(6, 300, 1, bpfEventTypeEnter))
	update = emit(8, 300, 2, bpfEventTypeExit)
	defer state.releaseTraceStateUpdate(update)
	if update.pendingEnter != nil {
		t.Fatal("second gap retained recovered pending")
	}
}

func TestIntegrityRecoveryRejectsFragmentFromAnotherInvocation(t *testing.T) {
	state := &TraceState{}
	state.TaintHistory()
	enter := traceEventEnvelope{valid: true, pid: 10, tid: 11, sysID: 1,
		enterTime: 100, eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter}
	state.handleEnvelope(enter)
	fragment := enter
	fragment.enterTime, fragment.eventFlags = 90, bpfEventFlagEnterFragment
	fragment.payload = []handler.PayloadSection{{Data: []byte("stale")}}
	state.handleEnvelope(fragment)
	exit := enter
	exit.eventType, exit.eventFlags = bpfEventTypeExit, 0
	update := state.handleEnvelope(exit)
	defer state.releaseTraceStateUpdate(update)
	if update.pendingEnter == nil || len(update.pendingEnter.payloadSections) != 0 {
		t.Fatal("recovered pair merged stale fragment")
	}
}

func TestIntegrityNonLeaderExecEndsOldIdentityWithoutRevivingHistory(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	i.InvalidRecord()
	i.tasks[11] = traceTaskIntegrity{pid: 10, epoch: i.snapshot.Epoch, clean: true, candidate: true}
	ev := traceEventEnvelope{valid: true, pid: 10, tid: 10, seq: 1,
		eventType: bpfEventTypeLifecycle, lifecycleAction: lifecycleExec, args: [6]uint64{11, 10}}
	i.Observe(&ev)
	if _, exists := i.tasks[11]; exists || !i.correlationTainted(10) || !ev.tainted {
		t.Fatalf("exec revived or retained old identity: %+v", i.Snapshot())
	}
	ev.seq, ev.lifecycleAction = 2, lifecycleFree
	i.Observe(&ev)
	if len(i.tasks) != 0 || !i.Snapshot().Tainted {
		t.Fatal("free must retire task correlation, not repair missing historical output")
	}
}

func TestIntegrityRepeatedSyscallCannotMergeAcrossTimeIdentity(t *testing.T) {
	state := &TraceState{}
	state.TaintHistory()
	enter := traceEventEnvelope{valid: true, pid: 10, tid: 11, seq: 1, sysID: 1,
		enterTime: 100, eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter}
	state.handleEnvelope(enter)
	exit := enter
	exit.eventType, exit.eventFlags, exit.enterTime = bpfEventTypeExit, 0, 200
	update := state.handleEnvelope(exit)
	defer state.releaseTraceStateUpdate(update)
	if update.pendingEnter != nil {
		t.Fatal("same syscall number matched a different invocation")
	}
}
