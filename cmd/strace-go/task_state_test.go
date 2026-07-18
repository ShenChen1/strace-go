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
	child := state.applyLifecycleEvent(fork)
	if child == nil || child.TID != 101 || child.TGID != 101 || child.ParentTID != 100 || !child.Alive {
		t.Fatalf("child task after fork = %+v", child)
	}
	if parent := state.tasks[100]; parent == nil || !parent.Alive || parent.LastAction != "fork" {
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
	execed := state.applyLifecycleEvent(exec)
	if execed == nil || !execed.Execed || !execed.Alive || execed.LastAction != "exec" {
		t.Fatalf("task after exec = %+v", execed)
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
	freed := state.applyLifecycleEvent(free)
	if freed == nil || freed.Alive || freed.LastAction != "free" {
		t.Fatalf("task after free = %+v", freed)
	}
}

func TestSyscallEventEnsuresTaskState(t *testing.T) {
	state := newTraceState()
	state.noteSyscallTask(syscallEventView{valid: true, pid: 200, tid: 201, enterTime: 40})

	task := state.tasks[201]
	if task == nil || task.TID != 201 || task.TGID != 200 || !task.Alive || task.LastSeenNS != 40 {
		t.Fatalf("task after syscall = %+v", task)
	}
}
