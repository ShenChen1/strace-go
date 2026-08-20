package main

import (
	"testing"

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
