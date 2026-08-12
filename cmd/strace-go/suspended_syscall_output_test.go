package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newSuspendedOutputForTest() (*SuspendedSyscallOutput, *TraceState, *bytes.Buffer) {
	state := newTraceState()
	out := &bytes.Buffer{}
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{
		Out:           out,
		Policy:        newTraceOutputPolicy(opts),
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	output := newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
		State:    state,
		Renderer: renderer,
	})
	return output, state, out
}

func TestSuspendedSyscallOutputPrintsUnfinishedAndRemembersState(t *testing.T) {
	output, state, out := newSuspendedOutputForTest()

	handled := output.HandleEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, probeRetEnter: 3},
		meta: meta.Syscall{Name: "nanosleep"},
	}, handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if !handled {
		t.Fatal("probe_ret_enter=3 should be handled")
	}
	if got := out.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
	if _, ok := state.suspendedSyscalls[101]; !ok {
		t.Fatal("suspended syscall state was not remembered")
	}
}

func TestSuspendedSyscallOutputUsesEventView(t *testing.T) {
	output, state, out := newSuspendedOutputForTest()
	ev := syscallEventContext{
		view: syscallEventView{valid: true, tid: 202, probeRetEnter: 3},
		meta: meta.Syscall{Name: "nanosleep"},
	}

	handled := output.HandleEvent(ev, handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if !handled {
		t.Fatal("view probe_ret_enter=3 should be handled")
	}
	if got := out.String(); got != "202   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
	if _, ok := state.suspendedSyscalls[202]; !ok {
		t.Fatal("suspended syscall state was not remembered from view tid")
	}
	if _, ok := state.suspendedSyscalls[1]; ok {
		t.Fatal("suspended syscall state used raw tid")
	}
}

func TestSuspendedSyscallOutputRemembersHandlerMetadataName(t *testing.T) {
	output, state, out := newSuspendedOutputForTest()
	ev := syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, probeRetEnter: 3},
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "nanosleep"},
		},
	}

	handled := output.HandleEvent(ev, handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if !handled {
		t.Fatal("probe_ret_enter=3 should be handled")
	}
	if got := out.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
	if got := state.suspendedSyscalls[101]; got != "nanosleep" {
		t.Fatalf("suspended syscall name = %q, want nanosleep", got)
	}
}

func TestSuspendedSyscallOutputConsumesSuppressedResumeProbe(t *testing.T) {
	output, state, out := newSuspendedOutputForTest()

	handled := output.HandleEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, probeRetEnter: 2},
		meta: meta.Syscall{Name: "nanosleep"},
	}, handler.Result{ArgParts: []string{"0x1"}})

	if !handled {
		t.Fatal("probe_ret_enter=2 should be consumed")
	}
	if out.Len() != 0 || len(state.suspendedSyscalls) != 0 {
		t.Fatalf("probe_ret_enter=2 side effects: out=%q state=%v", out.String(), state.suspendedSyscalls)
	}
}

func TestSuspendedSyscallOutputFallsThroughForNormalProbe(t *testing.T) {
	output, _, out := newSuspendedOutputForTest()

	handled := output.HandleEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, probeRetEnter: 0},
		meta: meta.Syscall{Name: "getpid"},
	}, handler.Result{})

	if handled {
		t.Fatal("normal probe should fall through")
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("normal probe output = %q, want no output", out.String())
	}
}
