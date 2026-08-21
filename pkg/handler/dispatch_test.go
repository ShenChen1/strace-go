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

func TestDispatchTableDecodePlanKeepsRequiredHandlers(t *testing.T) {
	custom := &dispatchTestHandler{}
	registry := NewRegistry()
	registry.Register("custom_no_args", custom)
	table := NewDispatchTable(registry, map[uint32]meta.Syscall{
		39:  {Name: "getpid"},
		1:   {Name: "write", ArgTypes: []string{"int"}},
		400: {Name: "custom_no_args"},
	})

	tests := []struct {
		name       string
		sysID      uint32
		syscall    string
		wantDecode bool
	}{
		{name: "empty default handler", sysID: 39, syscall: "getpid", wantDecode: false},
		{name: "default handler with arguments", sysID: 1, syscall: "write", wantDecode: true},
		{name: "custom handler without arguments", sysID: 400, syscall: "custom_no_args", wantDecode: true},
		{name: "unknown id keeps registry fallback", sysID: 999, syscall: "unknown", wantDecode: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := table.NeedsDecode(tt.sysID, tt.syscall); got != tt.wantDecode {
				t.Fatalf("NeedsDecode(%d, %q) = %v, want %v", tt.sysID, tt.syscall, got, tt.wantDecode)
			}
		})
	}
}
