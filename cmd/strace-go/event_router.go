package main

type TraceEventRouter struct {
	scope       TraceScope
	targetPID   int
	state       *TraceState
	lifecycle   *LifecycleEventHandler
	json        *SyscallJSONOutput
	pipeline    *SyscallExitPipeline
	contextDeps syscallEventContextDeps
}

type TraceEventRouterDeps struct {
	Scope       TraceScope
	TargetPID   int
	State       *TraceState
	Lifecycle   *LifecycleEventHandler
	JSON        *SyscallJSONOutput
	Pipeline    *SyscallExitPipeline
	ContextDeps syscallEventContextDeps
}

func newTraceEventRouter(deps TraceEventRouterDeps) *TraceEventRouter {
	return &TraceEventRouter{
		scope:       deps.Scope,
		targetPID:   deps.TargetPID,
		state:       deps.State,
		lifecycle:   deps.Lifecycle,
		json:        deps.JSON,
		pipeline:    deps.Pipeline,
		contextDeps: deps.ContextDeps,
	}
}

func (s *traceSession) traceEventRouter() *TraceEventRouter {
	if s.eventRouterCache == nil {
		s.eventRouterCache = newTraceEventRouter(TraceEventRouterDeps{
			Scope:       s.traceScope(),
			TargetPID:   s.targetPid,
			State:       s.traceState(),
			Lifecycle:   s.lifecycleEventHandler(),
			JSON:        s.syscallJSONOutput(),
			Pipeline:    s.syscallExitPipeline(),
			ContextDeps: newSyscallEventContextDeps(s),
		})
	}
	return s.eventRouterCache
}

// IMPACT: Handle is the single routing boundary after a ringbuf record is decoded.
func (r *TraceEventRouter) Handle(envelope traceEventEnvelope) {
	if !r.scope.AllowsPID(envelope.pid) {
		return
	}
	stateUpdate := r.traceState().handleEnvelope(envelope)
	statePID := eventStatePID(envelope, r.targetPID)

	switch stateUpdate.kind {
	case traceStateLifecycle:
		r.handleLifecycle(stateUpdate)
	case traceStateSyscallEnter:
		r.handleEnter(stateUpdate, statePID)
	case traceStateSyscallFragment:
		return
	default:
		r.handleExit(stateUpdate, statePID)
	}
}

func (r *TraceEventRouter) traceState() *TraceState {
	if r.state == nil {
		r.state = newTraceState()
	}
	return r.state
}

func (r *TraceEventRouter) handleLifecycle(update TraceStateUpdate) {
	if r.lifecycle != nil {
		r.lifecycle.Handle(update.lifecycleView, update.lifecycleTask)
	}
}

func (r *TraceEventRouter) handleEnter(update TraceStateUpdate, statePID int) {
	if r.json != nil {
		r.json.HandleEnter(newSyscallEnterEventContext(
			update.syscallView,
			statePID,
			update.payloadSections,
		))
	}
}

func (r *TraceEventRouter) handleExit(update TraceStateUpdate, statePID int) {
	if r.pipeline == nil {
		return
	}
	ev := newSyscallEventContextFromViewWithDeps(
		r.contextDeps,
		update.syscallView,
		statePID,
		update.pendingEnter,
		update.payloadSections,
	)
	r.pipeline.Handle(ev)
}

func eventStatePID(envelope traceEventEnvelope, targetPID int) int {
	if envelope.valid && envelope.pid != 0 {
		return int(envelope.pid)
	}
	return targetPID
}
