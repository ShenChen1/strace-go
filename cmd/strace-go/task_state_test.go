package main

import "testing"

func TestApplyLifecycleEventMaintainsTaskState(t *testing.T) {
	state := newTraceState()

	fork := lifecycleEventView{
		valid:     true,
		pid:       100,
		tid:       100,
		eventType: bpfEventTypeLifecycle,
		action:    lifecycleFork,
		enterTime: 10,
		args:      [6]uint64{100, 101},
	}
	child, inherit := state.applyLifecycleEvent(fork)
	if child == nil || child.TID != 101 || child.TGID != 0 || child.ParentTID != 100 || !child.Alive {
		t.Fatalf("child task after fork = %+v", child)
	}
	if inherit != nil {
		t.Fatalf("process inheritance after fork = %+v, want pending identity", inherit)
	}
	if parent := state.lifecycle.tasks[100]; parent == nil || !parent.Alive || parent.LastAction != "fork" {
		t.Fatalf("parent task after fork = %+v", parent)
	}

	exec := lifecycleEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		eventType: bpfEventTypeLifecycle,
		action:    lifecycleExec,
		enterTime: 20,
		args:      [6]uint64{101, 101},
	}
	execed, inherit := state.applyLifecycleEvent(exec)
	if execed == nil || !execed.Execed || !execed.Alive || execed.LastAction != "exec" {
		t.Fatalf("task after exec = %+v", execed)
	}
	if inherit == nil || inherit.parentTGID != 100 || inherit.childTGID != 101 {
		t.Fatalf("process inheritance after exec = %+v, want 100 -> 101", inherit)
	}

	free := lifecycleEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		eventType: bpfEventTypeLifecycle,
		action:    lifecycleFree,
		enterTime: 30,
		args:      [6]uint64{101},
	}
	freed, inherit := state.applyLifecycleEvent(free)
	if freed == nil || freed.Alive || freed.LastAction != "free" {
		t.Fatalf("task after free = %+v", freed)
	}
	if inherit != nil {
		t.Fatalf("process inheritance after free = %+v, want none", inherit)
	}
}

func TestApplyLifecycleEventOwnsExecutableState(t *testing.T) {
	state := newTraceState()
	parent := state.ensureTaskState(100, 100)
	parent.Executable = "/bin/parent"

	child, _ := state.applyLifecycleEvent(lifecycleEventView{
		pid:    100,
		tid:    100,
		action: lifecycleFork,
		args:   [6]uint64{100, 101},
	})
	if child == nil {
		t.Fatal("fork child task is nil")
	}
	if child.Executable != "/bin/parent" {
		t.Fatalf("fork child executable = %q, want inherited /bin/parent", child.Executable)
	}

	execed, _ := state.applyLifecycleEvent(lifecycleEventView{
		pid:          101,
		tid:          101,
		action:       lifecycleExec,
		args:         [6]uint64{101, 101},
		snapshotText: "/bin/child",
	})
	if execed == nil {
		t.Fatal("exec task is nil")
	}
	if execed.Executable != "/bin/child" {
		t.Fatalf("exec task executable = %q, want /bin/child", execed.Executable)
	}

	freed, _ := state.applyLifecycleEvent(lifecycleEventView{
		pid:    101,
		tid:    101,
		action: lifecycleFree,
	})
	if freed == nil {
		t.Fatal("free task is nil")
	}
	if freed.Executable != "/bin/child" {
		t.Fatalf("free task executable = %q, want retained /bin/child", freed.Executable)
	}
}

func TestApplyLifecycleExecClearsStaleExecutableWithoutSnapshot(t *testing.T) {
	state := newTraceState()
	task := state.ensureTaskState(101, 101)
	task.Executable = "/bin/old"

	execed, _ := state.applyLifecycleEvent(lifecycleEventView{
		pid:    101,
		tid:    101,
		action: lifecycleExec,
		args:   [6]uint64{101, 101},
	})

	if execed == nil {
		t.Fatal("exec task is nil")
	}
	if execed.Executable != "" {
		t.Fatalf("exec task executable = %q, want unknown after missing snapshot", execed.Executable)
	}
}

func TestTraceStateMigratesNonLeaderExecTaskWithoutDroppingPending(t *testing.T) {
	state := newTraceState()
	leader := state.ensureTaskState(200, 200)
	leader.ParentTID = 100
	leader.Executable = "/bin/parent"
	state.handleEnvelope(traceEventEnvelope{
		valid:      true,
		pid:        200,
		tid:        200,
		sysID:      syscallIDByName(t, "read"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  5,
	})

	execID := syscallIDByName(t, "execve")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        200,
		tid:        201,
		sysID:      execID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  10,
	}
	state.handleEnvelope(enter)
	worker := state.lifecycle.tasks[201]
	if worker == nil {
		t.Fatal("exec enter did not create worker task")
	}
	worker.ParentTID = 200
	worker.Executable = "/bin/parent"

	lifecycle := lifecycleEnvelopeForTask(200, 200, lifecycleExec, 201, 200)
	lifecycle.snapshotText = "/bin/true"
	update := state.handleEnvelope(lifecycle)
	if update.lifecycleTask == nil || update.lifecycleTask.TID != 200 {
		t.Fatalf("exec lifecycle task = %+v, want leader TID 200", update.lifecycleTask)
	}
	if update.lifecycleTask.ParentTID != 100 {
		t.Fatalf("exec lifecycle parent = %d, want existing leader parent 100", update.lifecycleTask.ParentTID)
	}
	if !update.lifecycleTask.ExecReplaced {
		t.Fatal("non-leader exec must retain replacement identity for final lifecycle cleanup")
	}
	if _, ok := state.lifecycle.tasks[201]; ok {
		t.Fatal("old non-leader task remains after exec lifecycle migration")
	}
	if state.correlation.pendingSyscalls[200] != nil {
		t.Fatal("exec lifecycle migration retained replaced leader pending syscall")
	}
	if state.correlation.pendingSyscalls[201] == nil {
		t.Fatal("exec lifecycle migration dropped old-TID pending syscall")
	}

	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	exit.ret = 0
	exitUpdate := state.handleEnvelope(exit)
	if exitUpdate.pendingEnter == nil {
		t.Fatal("successful non-leader exec exit did not pair old-TID enter")
	}
	if _, ok := state.lifecycle.tasks[201]; ok {
		t.Fatal("successful non-leader exec exit recreated old task identity")
	}
	if task := state.lifecycle.tasks[200]; task == nil || !task.Alive || task.Executable != "/bin/true" {
		t.Fatalf("migrated leader task = %+v, want alive /bin/true", task)
	}
}

func TestSyscallEventEnsuresTaskState(t *testing.T) {
	state := newTraceState()
	state.noteSyscallTask(&syscallEventView{valid: true, pid: 200, tid: 201, enterTime: 40})

	task := state.lifecycle.tasks[201]
	if task == nil || task.TID != 201 || task.TGID != 200 || !task.Alive || task.LastSeenNS != 40 {
		t.Fatalf("task after syscall = %+v", task)
	}
}

func TestApplyLifecycleEventResolvesThreadIdentityWithoutFDInheritance(t *testing.T) {
	state := newTraceState()
	child, inherit := state.applyLifecycleEvent(lifecycleEventView{
		pid:       200,
		tid:       200,
		action:    lifecycleFork,
		args:      [6]uint64{200, 201},
		enterTime: 10,
	})
	if child == nil || child.TGID != 0 || inherit != nil {
		t.Fatalf("thread child after fork = %+v inherit=%+v, want unknown TGID and pending relation", child, inherit)
	}

	resolved, inherit := state.applyLifecycleEvent(lifecycleEventView{
		pid:       200,
		tid:       201,
		action:    lifecycleExit,
		enterTime: 20,
	})
	if resolved == nil || resolved.TGID != 200 || resolved.Alive {
		t.Fatalf("thread child after exit = %+v, want TGID 200 and dead", resolved)
	}
	if inherit != nil {
		t.Fatalf("thread process inheritance = %+v, want none", inherit)
	}
}
