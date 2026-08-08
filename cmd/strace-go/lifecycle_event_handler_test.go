package main

import (
	"testing"

	"strace-go/pkg/cli"
)

type lifecycleHandlerTestState struct {
	handler *LifecycleEventHandler
	effects *fakeLifecycleEffects
}

type fakeLifecycleEffects struct {
	inherited     [][2]int
	cleaned       []int
	jsonEventSeen bool
	jsonTaskSeen  *TaskState
	exitText      []fakeLifecycleExitText
}

type fakeLifecycleExitText struct {
	tid      int
	exitCode uint64
}

func (e *fakeLifecycleEffects) InheritProcessState(parentPID int, childPID int) {
	e.inherited = append(e.inherited, [2]int{parentPID, childPID})
}

func (e *fakeLifecycleEffects) CleanupProcessState(pid int) {
	e.cleaned = append(e.cleaned, pid)
}

func (e *fakeLifecycleEffects) WriteJSON(_ lifecycleEventView, task *TaskState) {
	e.jsonEventSeen = true
	e.jsonTaskSeen = task
}

func (e *fakeLifecycleEffects) WriteExitText(tid int, exitCode uint64) {
	e.exitText = append(e.exitText, fakeLifecycleExitText{tid: tid, exitCode: exitCode})
}

func newLifecycleHandlerTestState(opts *cli.Options) *lifecycleHandlerTestState {
	state := &lifecycleHandlerTestState{effects: &fakeLifecycleEffects{}}
	state.handler = newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Opts:    opts,
		Effects: state.effects,
	})
	return state
}

func TestLifecycleEventHandlerHandlesForkAndJSON(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "/bin/true"})
	state := newLifecycleHandlerTestState(opts)
	task := &TaskState{TID: 101}

	state.handler.Handle(lifecycleEventView{
		action: lifecycleFork,
		args:   [6]uint64{100, 101},
	}, task)

	if len(state.effects.inherited) != 1 || state.effects.inherited[0] != [2]int{100, 101} {
		t.Fatalf("inherited = %v, want [100 101]", state.effects.inherited)
	}
	if len(state.effects.cleaned) != 0 {
		t.Fatalf("cleaned = %v, want none", state.effects.cleaned)
	}
	if !state.effects.jsonEventSeen || state.effects.jsonTaskSeen != task {
		t.Fatalf("json seen=%v task=%p, want task=%p", state.effects.jsonEventSeen, state.effects.jsonTaskSeen, task)
	}
}

func TestLifecycleEventHandlerHandlesExitAndFreeCleanup(t *testing.T) {
	state := newLifecycleHandlerTestState(nil)

	state.handler.Handle(lifecycleEventView{action: lifecycleExit, tid: 101}, nil)
	state.handler.Handle(lifecycleEventView{action: lifecycleFree, tid: 102}, nil)

	if len(state.effects.inherited) != 0 {
		t.Fatalf("inherited = %v, want none", state.effects.inherited)
	}
	if len(state.effects.cleaned) != 2 || state.effects.cleaned[0] != 101 || state.effects.cleaned[1] != 102 {
		t.Fatalf("cleaned = %v, want [101 102]", state.effects.cleaned)
	}
	if state.effects.jsonEventSeen {
		t.Fatal("json should not be written outside json mode")
	}
}

func TestLifecycleEventHandlerDoesNotCleanupProcessForNonLeaderThread(t *testing.T) {
	state := newLifecycleHandlerTestState(nil)

	state.handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		pid:    200,
		tid:    201,
	}, &TaskState{TID: 201, TGID: 200})

	if len(state.effects.cleaned) != 0 {
		t.Fatalf("cleaned = %v, want no process cleanup for non-leader thread", state.effects.cleaned)
	}

	state.handler.Handle(lifecycleEventView{
		action: lifecycleFree,
		pid:    200,
		tid:    201,
	}, &TaskState{TID: 201, TGID: 200})

	if len(state.effects.cleaned) != 0 {
		t.Fatalf("cleaned after free = %v, want no process cleanup for non-leader thread", state.effects.cleaned)
	}

	state.handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		pid:    200,
		tid:    200,
	}, &TaskState{TID: 200, TGID: 200})

	if len(state.effects.cleaned) != 1 || state.effects.cleaned[0] != 200 {
		t.Fatalf("cleaned = %v, want leader process cleanup [200]", state.effects.cleaned)
	}
}

func TestLifecycleEventHandlerSkipsJSONOutsideJSONMode(t *testing.T) {
	opts := cli.ParseArgs([]string{"/bin/true"})
	state := newLifecycleHandlerTestState(opts)

	state.handler.Handle(lifecycleEventView{action: lifecycleExec}, &TaskState{TID: 101})

	if state.effects.jsonEventSeen {
		t.Fatal("json should not be written for text mode")
	}
}

func TestLifecycleEventHandlerWritesExitTextThroughEffects(t *testing.T) {
	opts := cli.ParseArgs([]string{"-p", "101", "/bin/true"})
	state := newLifecycleHandlerTestState(opts)

	state.handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		tid:    101,
		args:   [6]uint64{7},
	}, &TaskState{TID: 101, TGID: 101})

	if len(state.effects.exitText) != 1 {
		t.Fatalf("exitText = %v, want one write", state.effects.exitText)
	}
	if got := state.effects.exitText[0]; got != (fakeLifecycleExitText{tid: 101, exitCode: 7}) {
		t.Fatalf("exitText[0] = %#v, want tid=101 exitCode=7", got)
	}
}
