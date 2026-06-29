package main

import "testing"

func TestApplyLifecycleEventMaintainsTaskState(t *testing.T) {
	session := &traceSession{}

	fork := &bpfEvent{
		Pid:        100,
		Tid:        100,
		EventType:  bpfEventTypeLifecycle,
		EventFlags: lifecycleFork,
		EnterTime:  10,
		Args:       [6]uint64{100, 101},
	}
	child := session.applyLifecycleEvent(fork)
	if child == nil || child.TID != 101 || child.TGID != 101 || child.ParentTID != 100 || !child.Alive {
		t.Fatalf("child task after fork = %+v", child)
	}
	if parent := session.tasks[100]; parent == nil || !parent.Alive || parent.LastAction != "fork" {
		t.Fatalf("parent task after fork = %+v", parent)
	}

	exec := &bpfEvent{
		Pid:        101,
		Tid:        101,
		EventType:  bpfEventTypeLifecycle,
		EventFlags: lifecycleExec,
		EnterTime:  20,
		Args:       [6]uint64{101, 101},
	}
	execed := session.applyLifecycleEvent(exec)
	if execed == nil || !execed.Execed || !execed.Alive || execed.LastAction != "exec" {
		t.Fatalf("task after exec = %+v", execed)
	}

	free := &bpfEvent{
		Pid:        101,
		Tid:        101,
		EventType:  bpfEventTypeLifecycle,
		EventFlags: lifecycleFree,
		EnterTime:  30,
		Args:       [6]uint64{101},
	}
	freed := session.applyLifecycleEvent(free)
	if freed == nil || freed.Alive || freed.LastAction != "free" {
		t.Fatalf("task after free = %+v", freed)
	}
}

func TestSyscallEventEnsuresTaskState(t *testing.T) {
	session := &traceSession{}
	session.noteSyscallTask(&bpfEvent{Pid: 200, Tid: 201, EnterTime: 40})

	task := session.tasks[201]
	if task == nil || task.TID != 201 || task.TGID != 200 || !task.Alive || task.LastSeenNS != 40 {
		t.Fatalf("task after syscall = %+v", task)
	}
}
