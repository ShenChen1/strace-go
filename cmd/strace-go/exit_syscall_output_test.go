package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type exitOutputTestState struct {
	output      *ExitSyscallOutput
	out         *bytes.Buffer
	queuedPID   int
	queuedLine  string
	jsonCalled  bool
	jsonEvent   syscallEventContext
	shouldQueue bool
}

func newExitOutputTestState(opts *cli.Options) *exitOutputTestState {
	out := &bytes.Buffer{}
	state := &exitOutputTestState{out: out}
	renderer := newTextRenderer(TextRendererDeps{
		Out:           out,
		Opts:          opts,
		State:         newTraceState(),
		TimeFormatter: newTimeFormatter(0),
	})
	state.output = newExitSyscallOutput(ExitSyscallOutputDeps{
		Opts:     opts,
		Renderer: renderer,
		Out:      out,
		ShouldQueueStatus: func(int) bool {
			return state.shouldQueue
		},
		QueueStatus: func(pid int, line string) {
			state.queuedPID = pid
			state.queuedLine = line
		},
		WriteJSON: func(ev syscallEventContext, _ handler.Result) {
			state.jsonCalled = true
			state.jsonEvent = ev
		},
	})
	return state
}

func exitEventContext(opts *cli.Options, name string, shouldPrint bool) syscallEventContext {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		ProbeRetEnter: -1,
		Args:          [6]uint64{7},
	}
	scMeta := meta.Syscall{Name: name, Args: []string{"error_code"}, ArgTypes: []string{"int"}}
	ctx := &handler.Context{
		ScMeta:  scMeta,
		SysName: name,
		Args:    eventRaw.Args,
		Opts:    opts,
	}
	return syscallEventContext{
		raw:            eventRaw,
		meta:           scMeta,
		shouldPrint:    shouldPrint,
		handlerContext: ctx,
	}
}

func TestExitSyscallOutputFallsThroughForNonExit(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{})
	ev := exitEventContext(state.output.opts, "getpid", true)

	if state.output.Handle(ev) {
		t.Fatal("non-exit syscall should fall through")
	}
	if state.out.Len() != 0 || state.jsonCalled || state.queuedLine != "" {
		t.Fatalf("non-exit side effects: out=%q json=%v queued=%q", state.out.String(), state.jsonCalled, state.queuedLine)
	}
}

func TestExitSyscallOutputPrintsTextAndStatus(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{FollowForks: true})

	if !state.output.Handle(exitEventContext(state.output.opts, "exit_group", true)) {
		t.Fatal("exit_group should be handled")
	}

	got := state.out.String()
	if !strings.Contains(got, "101   exit_group(7) = ?") || !strings.Contains(got, "101   +++ exited with 7 +++") {
		t.Fatalf("exit output = %q, want syscall and status lines", got)
	}
}

func TestExitSyscallOutputQueuesStatusWhenRequested(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{FollowForks: true})
	state.shouldQueue = true

	state.output.Handle(exitEventContext(state.output.opts, "exit", true))

	got := state.out.String()
	if !strings.Contains(got, "101   exit(7) = ?") {
		t.Fatalf("exit syscall output = %q, want syscall line before queued status", got)
	}
	if state.queuedPID != 101 || !strings.Contains(state.queuedLine, "+++ exited with 7 +++") {
		t.Fatalf("queued status = pid %d line %q, want pid 101 exit status", state.queuedPID, state.queuedLine)
	}
	if strings.Contains(got, "+++ exited") {
		t.Fatalf("queued exit status was printed immediately: %q", got)
	}
}

func TestExitSyscallOutputJSONReturnsBeforeStatusLine(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON})

	state.output.Handle(exitEventContext(state.output.opts, "exit_group", true))

	if !state.jsonCalled {
		t.Fatal("JSON exit event was not written")
	}
	if state.out.Len() != 0 || state.queuedLine != "" {
		t.Fatalf("JSON exit side effects: out=%q queued=%q", state.out.String(), state.queuedLine)
	}
}

func TestExitSyscallOutputJSONUsesEventContext(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON})
	ev := exitEventContext(state.output.opts, "exit_group", true)
	ev.raw.Ret = 123
	ev.view = syscallEventView{valid: true, ret: -2, probeRetEnter: -1}

	state.output.Handle(ev)

	if !state.jsonCalled {
		t.Fatal("JSON exit event was not written")
	}
	if state.jsonEvent.eventView().ret != -2 {
		t.Fatalf("json event ret = %d, want view ret -2", state.jsonEvent.eventView().ret)
	}
}

func TestExitSyscallOutputDetectsExitFromEventView(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON})
	ev := exitEventContext(state.output.opts, "exit_group", true)
	ev.raw.ProbeRetEnter = 0
	ev.view = syscallEventView{valid: true, probeRetEnter: -1}

	if !state.output.Handle(ev) {
		t.Fatal("exit_group should be handled from event view")
	}
	if !state.jsonCalled {
		t.Fatal("JSON exit event was not written")
	}
}

func TestExitSyscallOutputQuietExitSuppressesStatusOnly(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{FollowForks: true, QuietExit: true})

	state.output.Handle(exitEventContext(state.output.opts, "exit_group", true))

	got := state.out.String()
	if !strings.Contains(got, "101   exit_group(7) = ?") {
		t.Fatalf("quiet exit output = %q, want syscall line", got)
	}
	if strings.Contains(got, "+++ exited") {
		t.Fatalf("quiet exit output included status line: %q", got)
	}
}

func TestExitSyscallOutputSummaryOnlyConsumesExit(t *testing.T) {
	state := newExitOutputTestState(&cli.Options{SummaryOnly: true})

	if !state.output.Handle(exitEventContext(state.output.opts, "exit_group", true)) {
		t.Fatal("summary-only exit should still be consumed")
	}
	if state.out.Len() != 0 || state.jsonCalled || state.queuedLine != "" {
		t.Fatalf("summary-only side effects: out=%q json=%v queued=%q", state.out.String(), state.jsonCalled, state.queuedLine)
	}
}
