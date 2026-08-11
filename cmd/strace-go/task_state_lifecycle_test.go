package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceStateRetiresTaskAfterLifecycleFree(t *testing.T) {
	state := newTraceState()
	state.handleEnvelope(lifecycleEnvelopeForTask(100, 100, lifecycleFork, 100, 101))

	update := state.handleEnvelope(lifecycleEnvelopeForTask(100, 101, lifecycleFree, 101, 0))
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 101 {
		t.Fatalf("lifecycle snapshot = %+v, want child snapshot", update.lifecycleTask)
	}
	if _, ok := state.tasks[101]; ok {
		t.Fatal("freed task remains in active task state")
	}
	if _, ok := state.pendingForks[101]; ok {
		t.Fatal("freed task remains in pending fork state")
	}
}

func TestTraceStateDoesNotRetainUnfollowedForkChild(t *testing.T) {
	state := newTraceStateForSession(&cli.Options{FollowForks: false})

	update := state.handleEnvelope(lifecycleEnvelopeForTask(200, 200, lifecycleFork, 200, 201))
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 201 {
		t.Fatalf("fork snapshot = %+v, want child snapshot", update.lifecycleTask)
	}
	if _, ok := state.tasks[201]; ok {
		t.Fatal("unfollowed child remains in active task state")
	}
	if len(state.pendingForks) != 0 {
		t.Fatalf("pending forks = %v, want empty without follow-forks", state.pendingForks)
	}
}

func TestTraceStateRetiresTaskWhenTerminatingSyscallHasNoLifecycleEvent(t *testing.T) {
	state := newTraceState()
	id := syscallIDByName(t, "exit_group")
	state.rememberPendingExecArgs(300, "stale exec args")
	state.rememberSuspendedSyscall(300, "read")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        300,
		tid:        300,
		sysID:      id,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	}
	state.handleEnvelope(enter)
	if _, ok := state.tasks[300]; !ok {
		t.Fatal("terminating syscall enter did not create task state")
	}

	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	state.handleEnvelope(exit)
	if _, ok := state.tasks[300]; ok {
		t.Fatal("terminating syscall exit did not retire task state")
	}
	if _, ok := state.pendingExecArgs[300]; ok {
		t.Fatal("terminating syscall exit left pending exec args")
	}
	if _, ok := state.suspendedSyscalls[300]; ok {
		t.Fatal("terminating syscall exit left suspended syscall state")
	}
}

func lifecycleEnvelopeForTask(pid, tid, action uint32, arg0, arg1 uint64) traceEventEnvelope {
	return traceEventEnvelope{
		valid:           true,
		pid:             pid,
		tid:             tid,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: action,
		args:            [6]uint64{arg0, arg1},
	}
}
