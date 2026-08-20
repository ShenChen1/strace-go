package handler

import "strace-go/pkg/meta"

// HandlerDispatchPort resolves a syscall handler using the session dispatch table.
// Known syscall IDs are expected to use an array-backed lookup; unknown IDs may
// fall back to the session registry.
type HandlerDispatchPort interface {
	Handle(sysID uint32, name string, ctx *Context) Result
}

// DispatchTable is an immutable handler lookup table for one trace session.
// The registry remains available for unknown IDs and test-only custom names.
type DispatchTable struct {
	handlers []Handler
	registry RegistryPort
}

var _ HandlerDispatchPort = (*DispatchTable)(nil)

// NewDispatchTable builds the ID-indexed handler table before event processing.
func NewDispatchTable(registry RegistryPort, syscalls map[uint32]meta.Syscall) *DispatchTable {
	table := &DispatchTable{registry: registry}
	if registry == nil || len(syscalls) == 0 {
		return table
	}

	maxID := uint32(0)
	for id := range syscalls {
		if id > maxID {
			maxID = id
		}
	}
	table.handlers = make([]Handler, int(maxID)+1)
	for id, syscall := range syscalls {
		table.handlers[id] = registry.Resolve(syscall.Name)
	}
	return table
}

// Handle dispatches a syscall without repeating the known-name map lookup.
func (t *DispatchTable) Handle(sysID uint32, name string, ctx *Context) Result {
	if t == nil {
		return Result{}
	}
	if sysID < uint32(len(t.handlers)) {
		if h := t.handlers[sysID]; h != nil {
			return h.Handle(ctx)
		}
	}
	if t.registry == nil {
		return Result{}
	}
	h := t.registry.Resolve(name)
	if h == nil {
		return Result{}
	}
	return h.Handle(ctx)
}
