package main

type TraceEventRouter struct {
	scope            TraceScope
	state            traceEventState
	dispatcher       traceEventUpdateDispatcher
	stageDiagnostics *traceEventStageDiagnostics
}

type TraceEventRouterDeps struct {
	Scope            TraceScope
	State            traceEventState
	Dispatcher       traceEventUpdateDispatcher
	StageDiagnostics *traceEventStageDiagnostics
}

func newTraceEventRouter(deps TraceEventRouterDeps) *TraceEventRouter {
	return &TraceEventRouter{
		scope:            deps.Scope,
		state:            deps.State,
		dispatcher:       deps.Dispatcher,
		stageDiagnostics: deps.StageDiagnostics,
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
	if r.stageDiagnostics == nil {
		stateUpdate := r.state.handleEnvelope(envelope)
		if r.dispatcher != nil {
			r.dispatcher.Dispatch(envelope, stateUpdate)
		}
		r.state.releaseTraceStateUpdate(stateUpdate)
		return
	}
	sample := r.stageDiagnostics.begin()
	stateUpdate := r.state.handleEnvelope(envelope)
	stateEndNS := r.stageDiagnostics.now(sample)
	r.stageDiagnostics.recordState(sample, stateEndNS)
	if r.dispatcher != nil {
		dispatchStartNS := stateEndNS
		r.dispatcher.Dispatch(envelope, stateUpdate)
		dispatchEndNS := r.stageDiagnostics.now(sample)
		r.stageDiagnostics.recordDispatch(sample, dispatchStartNS, dispatchEndNS)
	}
	r.state.releaseTraceStateUpdate(stateUpdate)
}

func (r *TraceEventRouter) EventStageStats() traceEventStageStats {
	if r == nil || r.stageDiagnostics == nil {
		return traceEventStageStats{}
	}
	return r.stageDiagnostics.EventStageStats()
}

func eventStatePID(envelope traceEventEnvelope, targetPID int) int {
	if envelope.valid && envelope.pid != 0 {
		return int(envelope.pid)
	}
	return targetPID
}
