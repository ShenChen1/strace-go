package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newExecSyscallOutputForTest(opts *cli.Options) (*ExecSyscallOutput, *TraceState, *bytes.Buffer, *[]int) {
	state := newTraceState()
	out := &bytes.Buffer{}
	discarded := []int{}
	renderer := newTextRenderer(TextRendererDeps{
		Out:           out,
		Opts:          opts,
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	output := newExecSyscallOutput(ExecSyscallOutputDeps{
		Opts:     opts,
		State:    state,
		Renderer: renderer,
		DiscardExitStatus: func(pid int) {
			discarded = append(discarded, pid)
		},
	})
	return output, state, out, &discarded
}

func execOutputEvent(scMeta meta.Syscall, pid uint32, tid uint32, ret int64) syscallEventContext {
	return syscallEventContext{
		view: syscallEventView{valid: true, pid: pid, tid: tid, ret: ret},
		meta: scMeta,
	}
}

func TestExecSyscallOutputFallsThroughForNonExec(t *testing.T) {
	output, _, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})

	handled := output.HandleEvent(execOutputEvent(meta.Syscall{Name: "openat"}, 200, 200, 0), handler.Result{})

	if handled {
		t.Fatal("non-exec syscall should fall through")
	}
	if out.Len() != 0 {
		t.Fatalf("non-exec output = %q, want no output", out.String())
	}
}

func TestExecSyscallOutputLeaderRestartAndResume(t *testing.T) {
	output, state, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}

	if !output.HandleEvent(execOutputEvent(scMeta, 200, 200, -514), res) {
		t.Fatal("leader exec restart should be handled")
	}
	if out.Len() != 0 {
		t.Fatalf("leader exec restart output = %q, want no output", out.String())
	}
	if _, ok := state.pendingExecArgsFor(200); !ok {
		t.Fatal("leader exec restart did not remember args")
	}

	if !output.HandleEvent(execOutputEvent(scMeta, 200, 200, 0), res) {
		t.Fatal("leader exec success should be handled")
	}
	got := out.String()
	if !strings.Contains(got, `200   execve("/bin/true", ["true"], 0x1 /* 1 var */)`) || !strings.Contains(got, "= 0") {
		t.Fatalf("leader exec success output = %q", got)
	}
	if _, ok := state.pendingExecArgsFor(200); ok {
		t.Fatal("leader exec args were not consumed")
	}
}

func TestExecSyscallOutputLeaderRestartAndResumeFromEventView(t *testing.T) {
	output, state, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}
	restart := syscallEventContext{
		view: syscallEventView{valid: true, pid: 200, tid: 200, ret: -514},
		meta: scMeta,
	}
	success := restart
	success.view.ret = 0

	if !output.HandleEvent(restart, res) {
		t.Fatal("leader exec restart should be handled from event view")
	}
	if _, ok := state.pendingExecArgsFor(200); !ok {
		t.Fatal("leader exec restart did not remember view tid")
	}
	if _, ok := state.pendingExecArgsFor(1); ok {
		t.Fatal("leader exec restart used raw tid")
	}

	if !output.HandleEvent(success, res) {
		t.Fatal("leader exec success should be handled from event view")
	}
	got := out.String()
	if !strings.Contains(got, `200   execve("/bin/true", ["true"], 0x1 /* 1 var */)`) || !strings.Contains(got, "= 0") {
		t.Fatalf("leader exec success output = %q", got)
	}
	if _, ok := state.pendingExecArgsFor(200); ok {
		t.Fatal("leader exec args were not consumed from view tid")
	}
}

func TestExecSyscallOutputLeaderSuccessUsesExitSnapshotWhenRestartIsLate(t *testing.T) {
	output, _, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}
	exit := execOutputEvent(scMeta, 200, 200, 0)
	exit.view.eventType = bpfEventTypeExit

	if !output.HandleEvent(exit, res) {
		t.Fatal("leader exec success should be handled without an earlier restart marker")
	}
	got := out.String()
	if !strings.Contains(got, `200   execve("/bin/true", ["true"], 0x1 /* 1 var */)`) || !strings.Contains(got, "= 0") {
		t.Fatalf("leader exec success output = %q, want exit snapshot rendering", got)
	}
}

func TestExecSyscallOutputUsesEffectiveMetadata(t *testing.T) {
	output, state, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`}}

	handled := output.HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 200, ret: -514},
		handlerContext: &handler.Context{ScMeta: scMeta, SysName: "execve"},
	}, res)

	if !handled {
		t.Fatal("leader exec restart should use effective metadata")
	}
	if out.Len() != 0 {
		t.Fatalf("leader exec restart output = %q, want no output", out.String())
	}
	if got, ok := state.pendingExecArgsFor(200); !ok || got != `execve("/bin/true")` {
		t.Fatalf("pending exec args = %q ok=%v, want effective execve args", got, ok)
	}
}

func TestExecSyscallOutputNonLeaderSuperseded(t *testing.T) {
	output, state, out, discarded := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}

	if !output.HandleEvent(execOutputEvent(scMeta, 200, 201, -514), res) {
		t.Fatal("non-leader exec restart should be handled")
	}
	if _, ok := state.pendingExecArgsFor(201); !ok {
		t.Fatal("non-leader exec restart did not remember args")
	}
	if !output.HandleEvent(execOutputEvent(scMeta, 200, 201, 0), res) {
		t.Fatal("non-leader exec success should be handled")
	}

	got := out.String()
	for _, want := range []string{
		`201   execve("/bin/true", ["true"], 0x1 /* 1 var */ <unfinished ...>`,
		`200   +++ superseded by execve in pid 201 +++`,
		`200   <... execve resumed>) = 0`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("non-leader exec output missing %q in %q", want, got)
		}
	}
	if _, ok := state.pendingExecArgsFor(201); ok {
		t.Fatal("non-leader exec args were not deleted")
	}
	if len(*discarded) != 1 || (*discarded)[0] != 200 {
		t.Fatalf("discarded exit statuses = %v, want [200]", *discarded)
	}
}

func TestExecSyscallOutputNonLeaderSupersededFromEventView(t *testing.T) {
	output, state, out, discarded := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}
	restart := syscallEventContext{
		view: syscallEventView{valid: true, pid: 200, tid: 201, ret: -514},
		meta: scMeta,
	}
	success := restart
	success.view.ret = 0

	if !output.HandleEvent(restart, res) {
		t.Fatal("non-leader exec restart should be handled from event view")
	}
	if _, ok := state.pendingExecArgsFor(201); !ok {
		t.Fatal("non-leader exec restart did not remember view tid")
	}
	if !output.HandleEvent(success, res) {
		t.Fatal("non-leader exec success should be handled from event view")
	}

	got := out.String()
	for _, want := range []string{
		`201   execve("/bin/true", ["true"], 0x1 /* 1 var */ <unfinished ...>`,
		`200   +++ superseded by execve in pid 201 +++`,
		`200   <... execve resumed>) = 0`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("non-leader exec view output missing %q in %q", want, got)
		}
	}
	if _, ok := state.pendingExecArgsFor(201); ok {
		t.Fatal("non-leader exec args were not deleted from view tid")
	}
	if len(*discarded) != 1 || (*discarded)[0] != 200 {
		t.Fatalf("discarded exit statuses = %v, want view tgid [200]", *discarded)
	}
}

func TestExecSyscallOutputNonLeaderWithoutFollowForksCleansPendingArgs(t *testing.T) {
	output, state, out, _ := newExecSyscallOutputForTest(&cli.Options{})
	scMeta := meta.Syscall{Name: "execveat"}
	res := handler.Result{ArgParts: []string{`AT_FDCWD`, `"/bin/true"`}}

	handled := output.HandleEvent(execOutputEvent(scMeta, 200, 201, -514), res)

	if handled {
		t.Fatal("non-leader exec without -f should fall through to normal syscall printing")
	}
	if out.Len() != 0 {
		t.Fatalf("fallthrough output = %q, want no direct exec output", out.String())
	}
	if got, ok := state.pendingExecArgsFor(201); ok {
		t.Fatalf("pending exec args = %q, want cleanup before fallthrough", got)
	}
}
