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
	inherited      [][2]int
	cleaned        []int
	execCleared    []int
	jsonEventSeen  bool
	jsonTaskSeen   *TaskState
	exitText       []fakeLifecycleExitText
	execSuperseded []fakeLifecycleExecSuperseded
	unknownChild   []fakeUnknownChildEffect
}

type fakeLifecycleExitText struct {
	tid      int
	exitCode uint64
}

type fakeLifecycleExecSuperseded struct {
	oldPID    int
	newPID    int
	enterTime uint64
}

type fakeUnknownChildEffect struct {
	action uint32
	pid    int
	quiet  bool
}

func (e *fakeLifecycleEffects) InheritProcessState(parentPID int, childPID int) {
	e.inherited = append(e.inherited, [2]int{parentPID, childPID})
}

func (e *fakeLifecycleEffects) CleanupProcessState(pid int) {
	e.cleaned = append(e.cleaned, pid)
}

func (e *fakeLifecycleEffects) CloseOnExecState(pid int) {
	e.execCleared = append(e.execCleared, pid)
}

func (e *fakeLifecycleEffects) WriteJSON(_ lifecycleEventView, task *TaskState) {
	e.jsonEventSeen = true
	e.jsonTaskSeen = task
}

func (e *fakeLifecycleEffects) WriteExitText(tid int, exitCode uint64) {
	e.exitText = append(e.exitText, fakeLifecycleExitText{tid: tid, exitCode: exitCode})
}

func (e *fakeLifecycleEffects) WriteExecSuperseded(oldPID int, newPID int, enterTime uint64) {
	e.execSuperseded = append(e.execSuperseded, fakeLifecycleExecSuperseded{
		oldPID: oldPID, newPID: newPID, enterTime: enterTime,
	})
}

func (e *fakeLifecycleEffects) HandleUnknownChild(action uint32, pid int, quiet bool) {
	e.unknownChild = append(e.unknownChild, fakeUnknownChildEffect{action: action, pid: pid, quiet: quiet})
}

func newLifecycleHandlerTestState(opts *cli.Options) *lifecycleHandlerTestState {
	state := &lifecycleHandlerTestState{effects: &fakeLifecycleEffects{}}
	state.handler = newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Policy:  newTraceOutputPolicy(opts),
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

	if len(state.effects.inherited) != 0 {
		t.Fatalf("inherited = %v, want deferred identity resolution", state.effects.inherited)
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
	if len(state.effects.exitText) != 0 {
		t.Fatalf("unrelated exitText = %v, want none", state.effects.exitText)
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

func TestLifecycleEventHandlerClosesCloexecStateForExecProcess(t *testing.T) {
	state := newLifecycleHandlerTestState(nil)
	state.handler.Handle(lifecycleEventView{action: lifecycleExec, pid: 200, tid: 201}, &TaskState{
		TID:  201,
		TGID: 200,
	})

	if len(state.effects.execCleared) != 1 || state.effects.execCleared[0] != 200 {
		t.Fatalf("execCleared = %v, want [200]", state.effects.execCleared)
	}
}

func TestLifecycleEventHandlerWritesThreadExecSupersededText(t *testing.T) {
	state := newLifecycleHandlerTestState(&cli.Options{FollowForks: true})
	state.handler.Handle(lifecycleEventView{
		action:    lifecycleExec,
		pid:       200,
		tid:       201,
		args:      [6]uint64{201, 200},
		enterTime: 42,
	}, &TaskState{TID: 201, TGID: 200})

	want := fakeLifecycleExecSuperseded{oldPID: 200, newPID: 201, enterTime: 42}
	if len(state.effects.execSuperseded) != 1 || state.effects.execSuperseded[0] != want {
		t.Fatalf("exec superseded effects = %v, want [%+v]", state.effects.execSuperseded, want)
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

func TestLifecycleEventHandlerWritesFollowedChildExitText(t *testing.T) {
	state := newLifecycleHandlerTestState(&cli.Options{FollowForks: true})

	state.handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		pid:    202,
		tid:    202,
		args:   [6]uint64{11},
	}, &TaskState{TID: 202, TGID: 202, ParentTID: 101})

	if len(state.effects.exitText) != 1 {
		t.Fatalf("followed child exitText = %v, want one write", state.effects.exitText)
	}
}

func TestLifecycleEventHandlerSuppressesReplacedChildExitText(t *testing.T) {
	state := newLifecycleHandlerTestState(&cli.Options{FollowForks: true})

	state.handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		pid:    202,
		tid:    202,
		args:   [6]uint64{0},
	}, &TaskState{TID: 202, TGID: 202, ParentTID: 101, ExecReplaced: true})

	if len(state.effects.exitText) != 0 {
		t.Fatalf("replaced child exitText = %v, want none", state.effects.exitText)
	}
}

func TestLifecycleEventHandlerAcceptsFakeLifecyclePolicy(t *testing.T) {
	effects := &fakeLifecycleEffects{}
	handler := newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Policy:  fakeTraceLifecyclePolicy{attachPID: 101},
		Effects: effects,
	})

	handler.Handle(lifecycleEventView{
		action: lifecycleExit,
		tid:    101,
		args:   [6]uint64{9},
	}, &TaskState{TID: 101, TGID: 101})

	if len(effects.exitText) != 1 || effects.exitText[0] != (fakeLifecycleExitText{tid: 101, exitCode: 9}) {
		t.Fatalf("exitText = %v, want fake lifecycle policy target output", effects.exitText)
	}
}

func TestLifecycleEventHandlerAppliesUnknownChildQuietPolicy(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		action    uint32
		wantQuiet bool
	}{
		{name: "detach visible", args: []string{"/bin/true"}, action: lifecycleUnknownDetach},
		{name: "detach quiet", args: []string{"-q", "/bin/true"}, action: lifecycleUnknownDetach, wantQuiet: true},
		{name: "exit visible with q", args: []string{"-q", "/bin/true"}, action: lifecycleUnknownExit},
		{name: "exit quiet", args: []string{"--quiet=exit", "/bin/true"}, action: lifecycleUnknownExit, wantQuiet: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newLifecycleHandlerTestState(cli.ParseArgs(test.args))
			state.handler.Handle(lifecycleEventView{action: test.action, args: [6]uint64{202}}, nil)
			want := fakeUnknownChildEffect{action: test.action, pid: 202, quiet: test.wantQuiet}
			if len(state.effects.unknownChild) != 1 || state.effects.unknownChild[0] != want {
				t.Fatalf("unknown child effects = %+v, want %+v", state.effects.unknownChild, want)
			}
		})
	}
}
