package main

type TraceEventRouter struct {
	scope      TraceScope
	state      traceEventState
	dispatcher traceEventUpdateDispatcher
}

type TraceEventRouterDeps struct {
	Scope      TraceScope
	State      traceEventState
	Dispatcher traceEventUpdateDispatcher
}

func newTraceEventRouter(deps TraceEventRouterDeps) *TraceEventRouter {
	return &TraceEventRouter{
		scope:      deps.Scope,
		state:      deps.State,
		dispatcher: deps.Dispatcher,
	}
}

func (s *traceSession) traceEventRouter() *TraceEventRouter {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.eventRouter
}

// IMPACT: Handle is the single routing boundary after a ringbuf record is decoded.
func (r *TraceEventRouter) Handle(envelope traceEventEnvelope) {
	if r == nil || r.state == nil {
		return
	}
	if !r.scope.AllowsEvent(envelope.pid, envelope.tid) {
		return
	}
	stateUpdate := r.state.handleEnvelope(envelope)
	if r.dispatcher != nil {
		r.dispatcher.Dispatch(envelope, stateUpdate)
	}
	r.state.releaseTraceStateUpdate(stateUpdate)
}

func eventStatePID(envelope traceEventEnvelope, targetPID int) int {
	if envelope.valid && envelope.pid != 0 {
		return int(envelope.pid)
	}
	return targetPID
}
