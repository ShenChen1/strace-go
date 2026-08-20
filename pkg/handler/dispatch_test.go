package handler

import (
	"testing"

	"strace-go/pkg/meta"
)

type dispatchTestHandler struct {
	calls int
}

func (h *dispatchTestHandler) Handle(*Context) Result {
	h.calls++
	return Result{ReturnDesc: "dispatch"}
}

func TestDispatchTableRoutesKnownAndUnknownSyscalls(t *testing.T) {
	custom := &dispatchTestHandler{}
	registry := NewRegistry()
	registry.Register("dispatch_test", custom)
	table := NewDispatchTable(registry, map[uint32]meta.Syscall{
		39:  {Name: "getpid"},
		400: {Name: "dispatch_test"},
	})

	if got := table.Handle(400, "dispatch_test", &Context{}); got.ReturnDesc != "dispatch" {
		t.Fatalf("known syscall result = %+v, want custom dispatch", got)
	}
	if got := table.Handle(999, "dispatch_test", &Context{}); got.ReturnDesc != "dispatch" {
		t.Fatalf("unknown syscall result = %+v, want registry fallback", got)
	}
	if custom.calls != 2 {
		t.Fatalf("custom handler calls = %d, want 2", custom.calls)
	}
}
