package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newSyscallTextOutputForTest(opts *cli.Options) (*SyscallTextOutput, *TraceState, *bytes.Buffer) {
	state := newTraceState()
	out := &bytes.Buffer{}
	renderer := newTextRenderer(TextRendererDeps{
		Out:           out,
		Opts:          opts,
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	output := newSyscallTextOutput(SyscallTextOutputDeps{
		Opts: opts,
		Suspended: newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
			State:    state,
			Renderer: renderer,
		}),
		Exec: newExecSyscallOutput(ExecSyscallOutputDeps{
			Opts:     opts,
			State:    state,
			Renderer: renderer,
		}),
		Renderer: renderer,
	})
	return output, state, out
}

func syscallTextContext(name string) *handler.Context {
	scMeta := meta.Syscall{Name: name}
	return &handler.Context{
		ScMeta:  scMeta,
		SysName: name,
		Opts:    &cli.Options{},
	}
}

func syscallTextEvent(name string, pid uint32, tid uint32, ret int64, probeRetEnter int32) syscallEventContext {
	ctx := syscallTextContext(name)
	return syscallEventContext{
		view:           syscallEventView{valid: true, pid: pid, tid: tid, ret: ret, probeRetEnter: probeRetEnter},
		meta:           ctx.ScMeta,
		handlerContext: ctx,
	}
}

func TestSyscallTextOutputPrintsNormalSyscall(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{})

	output.HandleEvent(syscallTextEvent("getpid", 101, 101, 101, -1), handler.Result{})

	if got := out.String(); got != "getpid() = 101\n" {
		t.Fatalf("normal syscall output = %q", got)
	}
}

func TestSyscallTextOutputPrintsNormalSyscallFromEventView(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{FollowForks: true})
	ctx := syscallTextContext("getpid")
	ev := syscallEventContext{
		raw:            &bpfEvent{Tid: 1, Ret: 1},
		view:           syscallEventView{valid: true, tid: 101, ret: 202, probeRetEnter: -1},
		meta:           ctx.ScMeta,
		handlerContext: ctx,
	}

	output.HandleEvent(ev, handler.Result{})

	if got := out.String(); got != "101   getpid() = 202\n" {
		t.Fatalf("normal syscall output = %q", got)
	}
}

func TestSyscallTextOutputAppliesStatusFilterBeforePrinting(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{FailedOnly: true})

	output.HandleEvent(syscallTextEvent("getpid", 101, 101, 101, -1), handler.Result{})

	if out.Len() != 0 {
		t.Fatalf("status-filtered output = %q, want no output", out.String())
	}
}

func TestSyscallTextOutputAppliesStatusFilterFromEventView(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{FailedOnly: true})
	ctx := syscallTextContext("getpid")
	ev := syscallEventContext{
		raw:            &bpfEvent{Tid: 101, Ret: 101},
		view:           syscallEventView{valid: true, tid: 101, ret: -2, probeRetEnter: -1},
		meta:           ctx.ScMeta,
		handlerContext: ctx,
	}

	output.HandleEvent(ev, handler.Result{})

	if got := out.String(); !strings.Contains(got, "ENOENT") {
		t.Fatalf("status-filtered output = %q, want failed view ret to print", got)
	}
}

func TestSyscallTextOutputDelegatesSuspendedBeforeNormalPrint(t *testing.T) {
	output, state, out := newSyscallTextOutputForTest(&cli.Options{FollowForks: true})

	output.HandleEvent(syscallTextEvent("nanosleep", 101, 101, 0, 3), handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if got := out.String(); !strings.Contains(got, "101   nanosleep({tv_sec=1} <unfinished ...>") {
		t.Fatalf("suspended output = %q", got)
	}
	if _, ok := state.suspendedSyscalls[101]; !ok {
		t.Fatal("suspended output did not remember state")
	}
}

func TestSyscallTextOutputDelegatesExecBeforeNormalPrint(t *testing.T) {
	output, state, out := newSyscallTextOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	ctx := &handler.Context{ScMeta: scMeta, SysName: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`}}

	output.HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 200, ret: -514},
		meta:           scMeta,
		handlerContext: ctx,
	}, res)

	if out.Len() != 0 {
		t.Fatalf("exec restart output = %q, want no normal syscall line", out.String())
	}
	if _, ok := state.pendingExecArgsFor(200); !ok {
		t.Fatal("exec restart did not remember pending args")
	}
}

func TestSyscallTextOutputDelegatesExecFromEventView(t *testing.T) {
	output, state, out := newSyscallTextOutputForTest(&cli.Options{FollowForks: true})
	scMeta := meta.Syscall{Name: "execve"}
	ctx := &handler.Context{ScMeta: scMeta, SysName: "execve"}
	ev := syscallEventContext{
		raw:            &bpfEvent{Pid: 1, Tid: 1, Ret: 0},
		view:           syscallEventView{valid: true, pid: 200, tid: 200, ret: -514},
		meta:           scMeta,
		handlerContext: ctx,
	}

	output.HandleEvent(ev, handler.Result{ArgParts: []string{`"/bin/true"`}})

	if out.Len() != 0 {
		t.Fatalf("exec restart output = %q, want no normal syscall line", out.String())
	}
	if _, ok := state.pendingExecArgsFor(200); !ok {
		t.Fatal("exec restart did not remember view tid")
	}
}
