package main

import (
	"errors"
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
	state := newTraceStateForSession(newTraceEventPolicy(&cli.Options{FollowForks: false}))

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

func TestTraceStateKeepsTaskUntilLifecycleAfterTerminatingSyscall(t *testing.T) {
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
	task, ok := state.tasks[300]
	if !ok {
		t.Fatal("terminating syscall enter did not create task state")
	}
	task.Executable = "/bin/target"

	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	state.handleEnvelope(exit)
	if task := state.tasks[300]; task == nil || task.Executable != "/bin/target" {
		t.Fatalf("terminating syscall task = %+v, want retained executable", task)
	}
	if _, ok := state.pendingExecArgs[300]; ok {
		t.Fatal("terminating syscall exit left pending exec args")
	}
	if _, ok := state.suspendedSyscalls[300]; ok {
		t.Fatal("terminating syscall exit left suspended syscall state")
	}
	if _, ok := state.lifecyclePending[300]; !ok {
		t.Fatal("terminating syscall exit did not mark lifecycle pending")
	}

	update := state.handleEnvelope(lifecycleEnvelopeForTask(300, 300, lifecycleExit, 0, 0))
	if update.lifecycleTask == nil || update.lifecycleTask.Executable != "/bin/target" {
		t.Fatalf("lifecycle snapshot = %+v, want retained executable", update.lifecycleTask)
	}
	if _, ok := state.tasks[300]; ok {
		t.Fatal("lifecycle exit did not retire task state")
	}
}

func TestTraceStateTracksAttachRootsFromLifecycleEvents(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{400, 500})

	if state.AttachTargetsDone() {
		t.Fatal("attach roots were marked done before lifecycle events")
	}
	state.handleEnvelope(lifecycleEnvelopeForTask(400, 400, lifecycleExit, 0, 0))
	if state.AttachTargetsDone() {
		t.Fatal("remaining attach root was marked done too early")
	}
	state.handleEnvelope(lifecycleEnvelopeForTask(500, 500, lifecycleFree, 0, 0))
	if !state.AttachTargetsDone() {
		t.Fatal("attach roots remain after exit/free lifecycle events")
	}
}

func TestTraceStateTracksAttachRootTerminatingSyscall(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{600})
	id := syscallIDByName(t, "exit_group")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        600,
		tid:        600,
		sysID:      id,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	}
	state.handleEnvelope(enter)

	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	state.handleEnvelope(exit)

	if !state.AttachTargetsDone() {
		t.Fatal("terminating syscall did not retire attach root")
	}
}

func TestTraceStateRecordsCommandLifecycleExit(t *testing.T) {
	state := newTraceState()
	state.setCommandTargetPID(800)
	if exited, err := state.TargetLifecycleExited(800); err != nil || exited {
		t.Fatalf("TargetLifecycleExited() before event = %v/%v, want false/nil", exited, err)
	}

	state.handleEnvelope(lifecycleEnvelopeForTask(800, 800, lifecycleExit, 0, 0))

	if exited, err := state.TargetLifecycleExited(800); err != nil || !exited {
		t.Fatalf("TargetLifecycleExited() after event = %v/%v, want true/nil", exited, err)
	}
}

func TestTraceStateUsesBPFCommandExitFact(t *testing.T) {
	state := newTraceState()
	state.setAttachExitReader(&fakeTraceAttachExitReader{
		exited: map[uint32]bool{801: true},
	})

	if exited, err := state.TargetLifecycleExited(801); err != nil || !exited {
		t.Fatalf("TargetLifecycleExited() from BPF fact = %v/%v, want true/nil", exited, err)
	}
}

func TestTraceStatePropagatesBPFCommandExitFactFailure(t *testing.T) {
	state := newTraceState()
	wantErr := errors.New("command exit fact unavailable")
	state.setAttachExitReader(&fakeTraceAttachExitReader{err: wantErr})

	if _, err := state.TargetLifecycleExited(802); !errors.Is(err, wantErr) {
		t.Fatalf("TargetLifecycleExited() error = %v, want %v", err, wantErr)
	}
}

func TestTraceStateDoesNotRetireProcessAttachRootForThreadExit(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{700})
	state.handleEnvelope(lifecycleEnvelopeForTask(700, 701, lifecycleExit, 0, 0))

	if state.AttachTargetsDone() {
		t.Fatal("thread exit retired the process attach root")
	}
}

func TestTraceStateRetiresAttachedThreadRootByTID(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{701})
	state.handleEnvelope(lifecycleEnvelopeForTask(700, 701, lifecycleFree, 0, 0))

	if !state.AttachTargetsDone() {
		t.Fatal("attached thread root was not retired by its TID")
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
