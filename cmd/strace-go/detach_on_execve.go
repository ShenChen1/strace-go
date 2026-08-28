package main

type traceDetachOnExecveObserver interface {
	Observe(syscallEventContext) syscallEventContext
	ObserveLifecycle(lifecycleEventView)
	Enabled() bool
}

// traceDetachOnExecve owns the one-shot detach state for a tracing session.
type traceDetachOnExecve struct {
	enabled     bool
	skipInitial bool
	initialPID  uint32
	initialTime uint64
	initialExit bool
	reached     bool
}

var _ traceDetachOnExecveObserver = (*traceDetachOnExecve)(nil)

func newTraceDetachOnExecve(enabled bool, hasCommand bool) *traceDetachOnExecve {
	return &traceDetachOnExecve{
		enabled:     enabled,
		skipInitial: enabled && hasCommand,
	}
}

func (d *traceDetachOnExecve) ObserveLifecycle(view lifecycleEventView) {
	if d == nil || !d.enabled || d.reached || view.action != lifecycleExec {
		return
	}
	if d.skipInitial {
		d.skipInitial = false
		d.initialPID = view.pid
		d.initialTime = view.enterTime
		d.initialExit = true
		return
	}
	if d.initialExit && d.initialPID == view.pid {
		d.initialPID = 0
		d.initialTime = 0
		d.initialExit = false
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
	view := event.eventView()
	if d.initialExit && d.initialPID == view.pid {
		isInitial := view.enterTime <= d.initialTime
		d.initialPID = 0
		d.initialTime = 0
		d.initialExit = false
		if isInitial {
			return event
		}
	}
	event.detached = true
	event.detachedByExecPolicy = true
	if view.pid != 0 && view.pid != view.tid {
		return event
	}
	d.reached = true
	return event
}

func (d *traceDetachOnExecve) Enabled() bool {
	return d != nil && d.enabled
}

func (d *traceDetachOnExecve) Reached() bool {
	return d != nil && d.reached
}
