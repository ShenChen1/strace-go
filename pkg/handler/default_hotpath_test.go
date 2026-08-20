package handler

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestDefaultHandlerZeroArgumentPathDoesNotAllocate(t *testing.T) {
	ctx := &Context{ScMeta: meta.Syscall{Name: "getpid"}}
	decoder := &DefaultHandler{}

	allocs := testing.AllocsPerRun(100, func() {
		result := decoder.Handle(ctx)
		if result.ArgParts != nil {
			t.Fatalf("zero-argument result = %+v, want empty result", result)
		}
	})
	if allocs != 0 {
		t.Fatalf("zero-argument handler allocations = %.1f, want zero", allocs)
	}
}
