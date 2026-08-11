package handler

// RuntimeServices contains the session-scoped enrichment state used while
// formatting syscall events. A trace session owns one implementation and
// calls it from its single event-consumer goroutine.
type RuntimeServices interface {
	NextFiemapCall(pid int) int
}

// Runtime keeps formatter state local to one trace session. Keeping this state
type Runtime struct {
	fiemapCalls map[int]int
}

// NewRuntime creates an empty session-scoped runtime.
func NewRuntime() *Runtime {
	return &Runtime{
		fiemapCalls: make(map[int]int),
	}
}

// NextFiemapCall returns the one-based invocation number for a process within
// this runtime. It preserves fiemap's bounded synthetic fallback per session.
func (r *Runtime) NextFiemapCall(pid int) int {
	if r == nil {
		return 1
	}
	if r.fiemapCalls == nil {
		r.fiemapCalls = make(map[int]int)
	}
	r.fiemapCalls[pid]++
	return r.fiemapCalls[pid]
}
