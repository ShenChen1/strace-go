package main

import (
	"errors"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceTaskLifecycleStateZeroValueIsSafe(t *testing.T) {
	var owner traceTaskLifecycleState
	if owner.lifecycleEventObserved(1) || !owner.quiescent(1) {
		t.Fatal("zero-value lifecycle owner changed empty-state completion semantics")
	}

	owner.markLifecyclePending(1)
	owner.clearLifecyclePending(1)
	task := owner.ensureTaskState(1, 1)
	if task == nil || task.TID != 1 || task.TGID != 1 {
		t.Fatalf("zero-value task state = %+v", task)
	}
	owner.retireTask(1)
	if len(owner.tasks) != 0 {
		t.Fatalf("retired zero-value task map = %+v, want empty", owner.tasks)
	}
}

func TestTraceStateRetiresTaskAfterLifecycleFree(t *testing.T) {
	state := newTraceState()
	state.handleEnvelope(lifecycleEnvelopeForTask(100, 100, lifecycleFork, 100, 101))

	update := state.handleEnvelope(lifecycleEnvelopeForTask(100, 101, lifecycleFree, 101, 0))
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 101 {
		t.Fatalf("lifecycle snapshot = %+v, want child snapshot", update.lifecycleTask)
	}
	if _, ok := state.lifecycle.tasks[101]; ok {
		t.Fatal("freed task remains in active task state")
	}
	if _, ok := state.lifecycle.pendingForks[101]; ok {
		t.Fatal("freed task remains in pending fork state")
	}
}

func TestTraceStateDoesNotRetainUnfollowedForkChild(t *testing.T) {
	state := newTraceStateForSession(newTraceEventPolicy(&cli.Options{FollowForks: false}))

	update := state.handleEnvelope(lifecycleEnvelopeForTask(200, 200, lifecycleFork, 200, 201))
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 201 {
		t.Fatalf("fork snapshot = %+v, want child snapshot", update.lifecycleTask)
	}
	if _, ok := state.lifecycle.tasks[201]; ok {
		t.Fatal("unfollowed child remains in active task state")
	}
	if len(state.lifecycle.pendingForks) != 0 {
		t.Fatalf("pending forks = %v, want empty without follow-forks", state.lifecycle.pendingForks)
	}
}

func TestTraceStateTaintKeepsObservedForkChildForQuiescence(t *testing.T) {
	state := newTraceState()
	parent := state.ensureTaskState(250, 250)
	parent.Alive = true
	parent.Executable = "/bin/parent"
	state.TaintHistory()

	state.handleEnvelope(lifecycleEnvelopeForTask(250, 250, lifecycleFork, 250, 251))
	child := state.lifecycle.tasks[251]
	if child == nil || !child.Alive {
		t.Fatalf("observed post-gap child = %+v, want tracked alive", child)
	}
	if child.ParentTID != 0 || child.Executable != "" || len(state.lifecycle.pendingForks) != 0 {
		t.Fatalf("tainted fork inherited historical identity: child=%+v pending=%v", child, state.lifecycle.pendingForks)
	}

	state.handleEnvelope(lifecycleEnvelopeForTask(250, 250, lifecycleExit, 0, 0))
	if state.TargetLifecycleQuiescent(250) {
		t.Fatal("observed live child was ignored after parent exit")
	}
	state.handleEnvelope(lifecycleEnvelopeForTask(251, 251, lifecycleExit, 0, 0))
	if state.TargetLifecycleQuiescent(250) {
		t.Fatal("tainted lifecycle history incorrectly proved quiescence from observed tasks alone")
	}
}

func TestTraceStateTaintedLifecycleKeepsCurrentTaskFacts(t *testing.T) {
	state := newTraceState()
	state.TaintHistory()

	update := state.handleEnvelope(lifecycleEnvelopeForTask(260, 260, lifecycleFork, 260, 261))
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 261 || !update.lifecycleTask.Alive {
		t.Fatalf("tainted lifecycle task = %+v, want observed child alive", update.lifecycleTask)
	}
	if update.processInherit != nil {
		t.Fatalf("tainted lifecycle inherited process state: %+v", update.processInherit)
	}
	if event := newJSONLifecycleEvent(update.lifecycleView, update.lifecycleTask); !event.Alive {
		t.Fatalf("tainted lifecycle JSON lost observed liveness: %+v", event)
	}
}

func TestTraceStateTaintedLifecycleWithoutFollowForksCanQuiesce(t *testing.T) {
	state := newTraceStateForSession(newTraceEventPolicy(&cli.Options{FollowForks: false}))
	state.TaintHistory()

	if !state.TargetLifecycleQuiescent(270) {
		t.Fatal("lifecycle taint delayed completion without follow-forks")
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
	task, ok := state.lifecycle.tasks[300]
	if !ok {
		t.Fatal("terminating syscall enter did not create task state")
	}
	task.Executable = "/bin/target"

	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	state.handleEnvelope(exit)
	if task := state.lifecycle.tasks[300]; task == nil || task.Executable != "/bin/target" {
		t.Fatalf("terminating syscall task = %+v, want retained executable", task)
	}
	if _, ok := state.correlation.pendingExecArgs[300]; ok {
		t.Fatal("terminating syscall exit left pending exec args")
	}
	if _, ok := state.correlation.suspendedSyscalls[300]; ok {
		t.Fatal("terminating syscall exit left suspended syscall state")
	}
	if _, ok := state.lifecycle.lifecyclePending[300]; !ok {
		t.Fatal("terminating syscall exit did not mark lifecycle pending")
	}

	update := state.handleEnvelope(lifecycleEnvelopeForTask(300, 300, lifecycleExit, 0, 0))
	if update.lifecycleTask == nil || update.lifecycleTask.Executable != "/bin/target" {
		t.Fatalf("lifecycle snapshot = %+v, want retained executable", update.lifecycleTask)
	}
	if _, ok := state.lifecycle.tasks[300]; ok {
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
