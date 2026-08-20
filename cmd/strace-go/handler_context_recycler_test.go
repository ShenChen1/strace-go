package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestHandlerContextRecyclerClearsAndReusesContext(t *testing.T) {
	recycler := newHandlerContextRecycler()
	first := recycler.acquire()
	first.SysName = "getpid"
	first.PayloadSections = []handler.PayloadSection{{Data: []byte("payload")}}

	recycler.release(first)
	second := recycler.acquire()
	if second != first {
		t.Fatal("released handler context was not reused")
	}
	if second.SysName != "" || second.PayloadSections != nil {
		t.Fatalf("reused handler context retained state: %+v", second)
	}
}

func TestHandlerContextRecyclerPreservesSessionPorts(t *testing.T) {
	recycler := newHandlerContextRecycler()
	context := recycler.acquire()
	catalog := meta.NewCatalog("raw")
	registry := handler.NewRegistry()
	decoder := event.NewDecoder()
	opts := &cli.Options{}
	fdState := newFDStateStoreFromMaps(nil, nil)
	runtime := handler.NewRuntime()
	dispatch := handler.NewDispatchTable(registry, map[uint32]meta.Syscall{
		39: {Name: "getpid"},
	})
	eventFD := eventFDStateView{cwd: "/work"}
	context.Meta = catalog
	context.Registry = registry
	context.HandlerDispatch = dispatch
	context.Decoder = decoder
	context.Opts = opts
	context.FDStateView = fdState
	context.Runtime = runtime
	context.EventFDView = eventFD
	context.Pid = 101
	context.SysName = "write"
	context.Args = [6]uint64{1, 2, 3}
	context.PayloadSections = []handler.PayloadSection{{Data: []byte("payload")}}
	context.ScMeta = meta.Syscall{Name: "write"}

	recycler.release(context)
	got := recycler.acquire()
	if got.Meta != catalog || got.Registry != registry || got.HandlerDispatch != dispatch ||
		got.Decoder != decoder || got.Opts != opts || got.FDStateView != fdState || got.Runtime != runtime {
		t.Fatalf("session ports changed after release: %+v", got)
	}
	if got.Pid != 0 || got.SysName != "" || got.Args != ([6]uint64{}) ||
		got.PayloadSections != nil || got.ScMeta.Name != "" || got.EventFDView != nil {
		t.Fatalf("event state retained after release: %+v", got)
	}
}

func TestHandlerContextRecyclerAppliesConfiguredSessionPorts(t *testing.T) {
	catalog := meta.NewCatalog("raw")
	registry := handler.NewRegistry()
	decoder := event.NewDecoder()
	opts := &cli.Options{}
	fdState := newFDStateStoreFromMaps(nil, nil)
	runtime := handler.NewRuntime()
	dispatch := handler.NewDispatchTable(registry, map[uint32]meta.Syscall{
		39: {Name: "getpid"},
	})
	recycler := newHandlerContextRecycler()
	recycler.configureSessionPorts(handlerContextSessionPorts{
		meta:     catalog,
		registry: registry,
		dispatch: dispatch,
		decoder:  decoder,
		opts:     opts,
		fdState:  fdState,
		runtime:  runtime,
	})

	first := recycler.acquire()
	if first.Meta != catalog || first.Registry != registry || first.HandlerDispatch != dispatch ||
		first.Decoder != decoder || first.Opts != opts || first.FDStateView != fdState || first.Runtime != runtime {
		t.Fatalf("configured session ports not applied: %+v", first)
	}
	first.Pid = 101
	recycler.release(first)
	second := recycler.acquire()
	if second != first || second.Meta != catalog || second.Registry != registry ||
		second.HandlerDispatch != dispatch || second.Decoder != decoder || second.Opts != opts ||
		second.FDStateView != fdState || second.Runtime != runtime {
		t.Fatalf("reused configured session ports changed: %+v", second)
	}
}

func TestSyscallExitPipelineReleasesHandlerContext(t *testing.T) {
	recycler := newHandlerContextRecycler()
	context := recycler.acquire()
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Runner: newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
			HandleSyscall: func(string, *handler.Context) handler.Result { return handler.Result{} },
		}),
	})
	event := syscallEventContext{
		view:            syscallEventView{valid: true, eventType: bpfEventTypeExit},
		meta:            meta.Syscall{Name: "getpid"},
		shouldPrint:     true,
		handlerContext:  context,
		contextRecycler: recycler,
	}

	pipeline.Handle(event)
	if got := recycler.acquire(); got != context {
		t.Fatal("pipeline did not release handler context")
	}
}

func TestSyscallEventContextReusesReleasedContext(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{TargetPID: 101})
	deps := newSyscallEventContextDeps(session)
	deps.contextPool = newHandlerContextRecycler()
	view := syscallEventView{valid: true, sysID: benchmarkSyscallID("getpid")}

	first := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, nil)
	context := first.handlerContext
	first.releaseHandlerContext()
	second := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, nil)
	if second.handlerContext != context {
		t.Fatal("event context did not reuse released handler context")
	}
	second.releaseHandlerContext()
}
