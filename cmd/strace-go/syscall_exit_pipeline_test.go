package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type exitPipelineTestState struct {
	pipeline *SyscallExitPipeline
	effects  *fakeSyscallExitEffects
}

type fakeSyscallExitEffects struct {
	calls []string
}

func (e *fakeSyscallExitEffects) RecordSummary(syscallEventContext) {
	e.calls = append(e.calls, "summary")
}

func (e *fakeSyscallExitEffects) UpdateFDOffsets(syscallEventContext) {
	e.calls = append(e.calls, "offset")
}

func (e *fakeSyscallExitEffects) CleanupClosedFD(syscallEventContext) {
	e.calls = append(e.calls, "cleanup")
}

func newExitPipelineTestState(opts *cli.Options, runner *SyscallHandlerRunner, json *SyscallJSONOutput) *exitPipelineTestState {
	state := &exitPipelineTestState{effects: &fakeSyscallExitEffects{}}
	state.pipeline = newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:    opts,
		JSON:    json,
		Runner:  runner,
		Effects: state.effects,
	})
	return state
}

func exitPipelineEvent(name string) syscallEventContext {
	return exitPipelineEventWithView(name, syscallEventView{valid: true})
}

func exitPipelineEventWithView(name string, view syscallEventView) syscallEventContext {
	return syscallEventContext{
		view:           view,
		meta:           meta.Syscall{Name: name},
		shouldPrint:    true,
		handlerContext: &handler.Context{SysName: name, ScMeta: meta.Syscall{Name: name}},
	}
}

func TestSyscallExitPipelineDebugRawStopsAfterJSONAndRunsFDSideEffects(t *testing.T) {
	opts := &cli.Options{EventFormat: cli.EventFormatJSON, DebugEvents: true}
	var calls []string
	jsonOutput := newSyscallJSONOutput(SyscallJSONOutputDeps{
		Opts: opts,
		Writer: &fakeJSONEventWriter{
			onRaw: func(syscallEventContext) {
				calls = append(calls, "json-raw")
			},
		},
	})
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			calls = append(calls, "handler")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(opts, runner, jsonOutput)

	state.pipeline.Handle(exitPipelineEvent("getpid"))

	calls = append(calls, state.effects.calls...)
	wantCalls(t, calls, []string{"json-raw", "offset", "cleanup"})
}

func TestSyscallExitPipelineSummaryOnlyStopsBeforeHandler(t *testing.T) {
	opts := &cli.Options{SummaryOnly: true}
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			t.Fatal("handler should not run for summary-only events")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(opts, runner, nil)

	state.pipeline.Handle(exitPipelineEvent("getpid"))

	wantCalls(t, state.effects.calls, []string{"summary", "offset", "cleanup"})
}

func TestSyscallExitPipelineSuppressesArchPrctlSetFSText(t *testing.T) {
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			t.Fatal("handler should not run for suppressed arch_prctl")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(nil, runner, nil)
	ev := exitPipelineEventWithView("arch_prctl", syscallEventView{valid: true, args: [6]uint64{0x1002}})

	state.pipeline.Handle(ev)

	wantCalls(t, state.effects.calls, []string{"offset", "cleanup"})
}

func TestSyscallExitPipelineSuppressesArchPrctlFromEventView(t *testing.T) {
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			t.Fatal("handler should not run for suppressed arch_prctl")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(nil, runner, nil)
	ev := exitPipelineEventWithView(
		"arch_prctl",
		syscallEventView{valid: true, args: [6]uint64{0x1002}},
	)

	state.pipeline.Handle(ev)

	wantCalls(t, state.effects.calls, []string{"offset", "cleanup"})
}

func TestSyscallExitPipelineRunsHandlerForPrintableEvent(t *testing.T) {
	var calls []string
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			calls = append(calls, "handler")
			return handler.Result{}
		},
		Effects: handlerEffectFunc(func(syscallEventContext) {
			calls = append(calls, "fd-state")
		}),
	})
	state := newExitPipelineTestState(nil, runner, nil)

	state.pipeline.Handle(exitPipelineEvent("getpid"))

	calls = append(calls, state.effects.calls...)
	wantCalls(t, calls, []string{"handler", "fd-state", "offset", "cleanup"})
}

func TestSyscallExitPipelineSkipsUnfinishedDecodeOutsideTextMode(t *testing.T) {
	opts := &cli.Options{EventFormat: cli.EventFormatJSON}
	called := false
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			called = true
			return handler.Result{}
		},
	})
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:   opts,
		Runner: runner,
		Text:   newSyscallTextOutput(SyscallTextOutputDeps{Opts: opts}),
	})

	if pipeline.HandleUnfinished(exitPipelineEvent("read")) {
		t.Fatal("JSON unfinished event should not be rendered")
	}
	if called {
		t.Fatal("JSON unfinished event should not decode handler arguments")
	}
}

func TestSyscallExitPipelineSkipsUnfinishedDecodeWithStatusFilter(t *testing.T) {
	opts := &cli.Options{SuccessfulOnly: true}
	called := false
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			called = true
			return handler.Result{}
		},
	})
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:   opts,
		Runner: runner,
		Text:   newSyscallTextOutput(SyscallTextOutputDeps{Opts: opts}),
	})

	if pipeline.HandleUnfinished(exitPipelineEvent("read")) {
		t.Fatal("status-filtered unfinished event should not be rendered")
	}
	if called {
		t.Fatal("status-filtered unfinished event should not decode handler arguments")
	}
}

type handlerEffectFunc func(syscallEventContext)

func (fn handlerEffectFunc) UpdateFDState(ev syscallEventContext) {
	fn(ev)
}

func wantCalls(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}
