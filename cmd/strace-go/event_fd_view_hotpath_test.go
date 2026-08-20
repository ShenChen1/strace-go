package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextOmitsEmptyEventFDView(t *testing.T) {
	deps := syscallEventContextDeps{
		filter:      newTraceFilterOptions(nil),
		contextPool: newHandlerContextRecycler(),
	}
	ev := newSyscallEventContextFromViewWithDeps(
		deps,
		syscallEventView{valid: true, sysID: benchmarkSyscallID("getpid")},
		101,
		nil,
		nil,
	)
	defer ev.releaseHandlerContext()

	if ev.handlerContext.EventFDView != nil {
		t.Fatalf("empty event FD view = %T, want nil", ev.handlerContext.EventFDView)
	}
}

var _ handler.EventFDStateReader = eventFDStateView{}
