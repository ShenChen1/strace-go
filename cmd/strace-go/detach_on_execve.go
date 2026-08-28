package main

type traceDetachOnExecveObserver interface {
	Observe(syscallEventContext) syscallEventContext
	Enabled() bool
}

// traceDetachOnExecve owns the one-shot detach state for a tracing session.
type traceDetachOnExecve struct {
	enabled     bool
	skipInitial bool
	reached     bool
}

var _ traceDetachOnExecveObserver = (*traceDetachOnExecve)(nil)

func newTraceDetachOnExecve(enabled bool, hasCommand bool) *traceDetachOnExecve {
	return &traceDetachOnExecve{
		enabled:     enabled,
		skipInitial: enabled && hasCommand,
	}
}

func (d *traceDetachOnExecve) Observe(event syscallEventContext) syscallEventContext {
	if d == nil || !d.enabled || d.reached || event.eventView().ret != 0 ||
		!isExecSyscall(event.syscallName()) {
		return event
	}
	if d.skipInitial {
		d.skipInitial = false
		return event
	}
	event.detached = true
	d.reached = true
	return event
}

func (d *traceDetachOnExecve) Enabled() bool {
	return d != nil && d.enabled
}

func (d *traceDetachOnExecve) Reached() bool {
	return d != nil && d.reached
}
