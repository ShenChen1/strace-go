package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type handlerRunnerTestState struct {
	runner       *SyscallHandlerRunner
	handledNames []string
	updates      int
}

func newHandlerRunnerTestState(result handler.Result) *handlerRunnerTestState {
	state := &handlerRunnerTestState{}
	state.runner = newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(name string, _ *handler.Context) handler.Result {
			state.handledNames = append(state.handledNames, name)
			return result
		},
		UpdateFDState: func(syscallEventContext) {
			state.updates++
		},
	})
	return state
}

func handlerRunnerEvent(name string, shouldPrint bool) syscallEventContext {
	return syscallEventContext{
		meta:           meta.Syscall{Name: name},
		shouldPrint:    shouldPrint,
		handlerContext: &handler.Context{SysName: name},
	}
}

func TestSyscallHandlerRunnerHandlesPrintedEventAndUpdatesFDState(t *testing.T) {
	state := newHandlerRunnerTestState(handler.Result{ArgParts: []string{"ok"}})

	res, shouldOutput := state.runner.Handle(handlerRunnerEvent("getpid", true))

	if !shouldOutput {
		t.Fatal("printed event should continue to output")
	}
	if len(res.ArgParts) != 1 || res.ArgParts[0] != "ok" {
		t.Fatalf("handler result = %+v, want ok arg", res)
	}
	if got := state.handledNames; len(got) != 1 || got[0] != "getpid" {
		t.Fatalf("handledNames = %v, want [getpid]", got)
	}
	if state.updates != 1 {
		t.Fatalf("updates = %d, want 1", state.updates)
	}
}

func TestSyscallHandlerRunnerRunsHiddenFDStateSyscallHandler(t *testing.T) {
	state := newHandlerRunnerTestState(handler.Result{})

	_, shouldOutput := state.runner.Handle(handlerRunnerEvent("openat", false))

	if shouldOutput {
		t.Fatal("hidden event should not continue to output")
	}
	if got := state.handledNames; len(got) != 1 || got[0] != "openat" {
		t.Fatalf("handledNames = %v, want [openat]", got)
	}
	if state.updates != 1 {
		t.Fatalf("updates = %d, want 1", state.updates)
	}
}

func TestSyscallHandlerRunnerSkipsHiddenNonFDStateSyscallHandler(t *testing.T) {
	state := newHandlerRunnerTestState(handler.Result{})

	_, shouldOutput := state.runner.Handle(handlerRunnerEvent("getpid", false))

	if shouldOutput {
		t.Fatal("hidden event should not continue to output")
	}
	if len(state.handledNames) != 0 {
		t.Fatalf("handledNames = %v, want none", state.handledNames)
	}
	if state.updates != 1 {
		t.Fatalf("updates = %d, want 1", state.updates)
	}
}
