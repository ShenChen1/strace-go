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
	policy := newTraceOutputPolicy(opts)
	renderer := newTextRenderer(TextRendererDeps{
		Out:           out,
		Policy:        policy,
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	output := newSyscallTextOutput(SyscallTextOutputDeps{
		Format: policy,
		Policy: policy,
		Suspended: newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
			State:    state,
			Renderer: renderer,
		}),
		Exec: newExecSyscallOutput(ExecSyscallOutputDeps{
			Policy:   policy,
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
		view:           syscallEventView{valid: true, tid: 101, ret: 202, probeRetEnter: -1},
		meta:           ctx.ScMeta,
		handlerContext: ctx,
	}

	output.HandleEvent(ev, handler.Result{})

	if got := out.String(); got != "101   getpid() = 202\n" {
		t.Fatalf("normal syscall output = %q", got)
	}
}

func TestSyscallTextOutputPrintsGenericUnfinishedAndResumed(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{FollowForks: true})
	pending := &pendingSyscallSnapshot{
		pid:       100,
		tid:       101,
		sysID:     syscallIDByName(t, "read"),
		enterTime: 10,
		args:      [6]uint64{3, 0x2000, 4},
	}
	enter := syscallEventContext{
		view:        syscallEventView{valid: true, pid: 100, tid: 101, enterTime: 10},
		meta:        meta.Syscall{Name: "read"},
		shouldPrint: true,
	}
	output.HandleUnfinished(enter, handler.Result{ArgParts: []string{"3", "\"\"", "4"}})
	pending.unfinishedPrinted = true

	exit := enter
	exit.view.eventType = bpfEventTypeExit
	exit.view.ret = 4
	exit.pendingEnter = pending
	output.HandleEvent(exit, handler.Result{})

	got := out.String()
	if !strings.Contains(got, "101   read(3, \"\", 4 <unfinished ...>") {
		t.Fatalf("generic unfinished output = %q", got)
	}
	if !strings.Contains(got, "101   <... read resumed>) = 4") {
		t.Fatalf("generic resumed output = %q", got)
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
	if _, ok := state.correlation.suspendedSyscalls[101]; !ok {
		t.Fatal("suspended output did not remember state")
	}
}

func TestSyscallTextOutputRendersSuspendedEventForUnfinishedStatus(t *testing.T) {
	output, _, out := newSyscallTextOutputForTest(&cli.Options{
		FollowForks:      true,
		StatusConfigured: true,
		TraceStatus:      map[string]bool{"unfinished": true},
	})

	output.HandleEvent(syscallTextEvent("nanosleep", 101, 101, 0, 3), handler.Result{
		ArgParts: []string{"{tv_sec=1}", "0x0"},
	})

	if got := out.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished status output = %q", got)
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
