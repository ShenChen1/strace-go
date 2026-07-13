package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type exitPipelineTestState struct {
	pipeline *SyscallExitPipeline
	calls    []string
}

func newExitPipelineTestState(opts *cli.Options, runner *SyscallHandlerRunner, json *SyscallJSONOutput) *exitPipelineTestState {
	state := &exitPipelineTestState{}
	state.pipeline = newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:   opts,
		JSON:   json,
		Runner: runner,
		RecordSummary: func(syscallEventContext) {
			state.calls = append(state.calls, "summary")
		},
		UpdateFDOffsets: func(syscallEventContext) {
			state.calls = append(state.calls, "offset")
		},
		CleanupClosedFD: func(syscallEventContext) {
			state.calls = append(state.calls, "cleanup")
		},
	})
	return state
}

func exitPipelineEvent(name string) syscallEventContext {
	return syscallEventContext{
		raw:            &bpfEvent{},
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
		WriteRaw: func(syscallEventContext) {
			calls = append(calls, "json-raw")
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

	calls = append(calls, state.calls...)
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

	wantCalls(t, state.calls, []string{"summary", "offset", "cleanup"})
}

func TestSyscallExitPipelineSuppressesArchPrctlSetFSText(t *testing.T) {
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			t.Fatal("handler should not run for suppressed arch_prctl")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(nil, runner, nil)
	ev := exitPipelineEvent("arch_prctl")
	ev.raw.Args[0] = 0x1002

	state.pipeline.Handle(ev)

	wantCalls(t, state.calls, []string{"offset", "cleanup"})
}

func TestSyscallExitPipelineSuppressesArchPrctlFromEventView(t *testing.T) {
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			t.Fatal("handler should not run for suppressed arch_prctl")
			return handler.Result{}
		},
	})
	state := newExitPipelineTestState(nil, runner, nil)
	ev := exitPipelineEvent("arch_prctl")
	ev.raw.Args[0] = 0
	ev.view = syscallEventView{valid: true, args: [6]uint64{0x1002}}

	state.pipeline.Handle(ev)

	wantCalls(t, state.calls, []string{"offset", "cleanup"})
}

func TestSyscallExitPipelineRunsHandlerForPrintableEvent(t *testing.T) {
	var calls []string
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			calls = append(calls, "handler")
			return handler.Result{}
		},
		UpdateFDState: func(syscallEventContext) {
			calls = append(calls, "fd-state")
		},
	})
	state := newExitPipelineTestState(nil, runner, nil)

	state.pipeline.Handle(exitPipelineEvent("getpid"))

	calls = append(calls, state.calls...)
	wantCalls(t, calls, []string{"handler", "fd-state", "offset", "cleanup"})
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
