package main

import (
	"testing"

	"strace-go/pkg/cli"
)

type lifecycleHandlerTestState struct {
	handler       *LifecycleEventHandler
	inherited     [][2]int
	cleaned       []int
	jsonEventSeen bool
	jsonTaskSeen  *TaskState
}

func newLifecycleHandlerTestState(opts *cli.Options) *lifecycleHandlerTestState {
	state := &lifecycleHandlerTestState{}
	state.handler = newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Opts: opts,
		Inherit: func(parentPID int, childPID int) {
			state.inherited = append(state.inherited, [2]int{parentPID, childPID})
		},
		Cleanup: func(pid int) {
			state.cleaned = append(state.cleaned, pid)
		},
		WriteJSON: func(_ traceStateEventView, task *TaskState) {
			state.jsonEventSeen = true
			state.jsonTaskSeen = task
		},
	})
	return state
}

func TestLifecycleEventHandlerHandlesForkAndJSON(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "/bin/true"})
	state := newLifecycleHandlerTestState(opts)
	task := &TaskState{TID: 101}

	state.handler.Handle(traceStateEventView{
		eventFlags: lifecycleFork,
		args:       [6]uint64{100, 101},
	}, task)

	if len(state.inherited) != 1 || state.inherited[0] != [2]int{100, 101} {
		t.Fatalf("inherited = %v, want [100 101]", state.inherited)
	}
	if len(state.cleaned) != 0 {
		t.Fatalf("cleaned = %v, want none", state.cleaned)
	}
	if !state.jsonEventSeen || state.jsonTaskSeen != task {
		t.Fatalf("json seen=%v task=%p, want task=%p", state.jsonEventSeen, state.jsonTaskSeen, task)
	}
}

func TestLifecycleEventHandlerHandlesExitAndFreeCleanup(t *testing.T) {
	state := newLifecycleHandlerTestState(nil)

	state.handler.Handle(traceStateEventView{eventFlags: lifecycleExit, tid: 101}, nil)
	state.handler.Handle(traceStateEventView{eventFlags: lifecycleFree, tid: 102}, nil)

	if len(state.inherited) != 0 {
		t.Fatalf("inherited = %v, want none", state.inherited)
	}
	if len(state.cleaned) != 2 || state.cleaned[0] != 101 || state.cleaned[1] != 102 {
		t.Fatalf("cleaned = %v, want [101 102]", state.cleaned)
	}
	if state.jsonEventSeen {
		t.Fatal("json should not be written outside json mode")
	}
}

func TestLifecycleEventHandlerSkipsJSONOutsideJSONMode(t *testing.T) {
	opts := cli.ParseArgs([]string{"/bin/true"})
	state := newLifecycleHandlerTestState(opts)

	state.handler.Handle(traceStateEventView{eventFlags: lifecycleExec}, &TaskState{TID: 101})

	if state.jsonEventSeen {
		t.Fatal("json should not be written for text mode")
	}
}
