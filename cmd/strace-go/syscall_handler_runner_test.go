package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type handlerRunnerTestState struct {
	runner       *SyscallHandlerRunner
	handledNames []string
	effects      *fakeSyscallHandlerEffects
}

type runnerDispatchHandler struct{}

func (runnerDispatchHandler) Handle(*handler.Context) handler.Result {
	return handler.Result{ReturnDesc: "dispatch-table"}
}

type fakeSyscallHandlerEffects struct {
	updates int
}

func (e *fakeSyscallHandlerEffects) UpdateFDState(syscallEventContext) {
	e.updates++
}

func newHandlerRunnerTestState(result handler.Result) *handlerRunnerTestState {
	state := &handlerRunnerTestState{effects: &fakeSyscallHandlerEffects{}}
	state.runner = newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(name string, _ *handler.Context) handler.Result {
			state.handledNames = append(state.handledNames, name)
			return result
		},
		Effects: state.effects,
	})
	return state
}

func handlerRunnerEvent(name string, shouldPrint bool) syscallEventContext {
	return syscallEventContext{
		view:           syscallEventView{valid: true},
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
	if state.effects.updates != 0 {
		t.Fatalf("updates = %d, want no-op getpid effect", state.effects.updates)
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
	if state.effects.updates != 1 {
		t.Fatalf("updates = %d, want 1", state.effects.updates)
	}
}

func TestSyscallHandlerRunnerKeepsPayloadFDStateEffect(t *testing.T) {
	state := newHandlerRunnerTestState(handler.Result{})
	event := handlerRunnerEvent("getpid", true)
	event.payloadSections = []handler.PayloadSection{{
		Kind:      handler.PayloadKindBytes,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		UserPtr:   0x1000,
		CopiedLen: 1,
		Data:      []byte{1},
	}}

	state.runner.Handle(event)

	if state.effects.updates != 1 {
		t.Fatalf("updates = %d, want payload-backed FD state effect", state.effects.updates)
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
	if state.effects.updates != 0 {
		t.Fatalf("updates = %d, want no-op hidden getpid effect", state.effects.updates)
	}
}

func TestSyscallHandlerRunnerUsesBoundDispatchBeforeFallback(t *testing.T) {
	registry := handler.NewRegistry()
	registry.Register("dispatch_test", runnerDispatchHandler{})
	dispatch := handler.NewDispatchTable(registry, map[uint32]meta.Syscall{
		400: {Name: "dispatch_test"},
	})
	event := handlerRunnerEvent("dispatch_test", true)
	event.handlerContext.SysId = 400
	event.handlerContext.HandlerDispatch = dispatch
	fallbackCalled := false
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			fallbackCalled = true
			return handler.Result{ReturnDesc: "fallback"}
		},
	})

	got, shouldOutput := runner.Handle(event)
	if !shouldOutput {
		t.Fatal("dispatch-backed event should continue to output")
	}
	if got.ReturnDesc != "dispatch-table" {
		t.Fatalf("handler result = %+v, want dispatch-table result", got)
	}
	if fallbackCalled {
		t.Fatal("fallback handler ran before bound dispatch")
	}
}

func TestSyscallHandlerRunnerDecodeUsesBoundDispatchWithoutFallback(t *testing.T) {
	registry := handler.NewRegistry()
	registry.Register("dispatch_test", runnerDispatchHandler{})
	dispatch := handler.NewDispatchTable(registry, map[uint32]meta.Syscall{
		400: {Name: "dispatch_test"},
	})
	event := handlerRunnerEvent("dispatch_test", true)
	event.handlerContext.SysId = 400
	event.handlerContext.HandlerDispatch = dispatch
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{})

	got := runner.Decode(event)
	if got.ReturnDesc != "dispatch-table" {
		t.Fatalf("decoded handler result = %+v, want dispatch-table result", got)
	}
}

func TestDefaultHandleSyscallWithoutRegistryIsInert(t *testing.T) {
	result := defaultHandleSyscall("getpid", &handler.Context{SysName: "getpid"})
	if len(result.ArgParts) != 0 || result.ReturnDesc != "" || result.HexDumpStr != "" {
		t.Fatalf("default handler without registry = %+v, want inert result", result)
	}
}

func TestDefaultHandleSyscallUsesSessionDispatchTable(t *testing.T) {
	registry := handler.NewRegistry()
	registry.Register("dispatch_test", runnerDispatchHandler{})
	dispatch := handler.NewDispatchTable(registry, map[uint32]meta.Syscall{
		400: {Name: "dispatch_test"},
	})
	ctx := &handler.Context{
		SysId:           400,
		Registry:        registry,
		HandlerDispatch: dispatch,
	}

	got := defaultHandleSyscall("dispatch_test", ctx)
	if got.ReturnDesc != "dispatch-table" {
		t.Fatalf("dispatch result = %+v, want session dispatch table result", got)
	}
}
