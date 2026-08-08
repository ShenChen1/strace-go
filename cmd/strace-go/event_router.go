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
	r.applyProcessStateInheritance(stateUpdate.processInherit)
	r.handleUnfinished(stateUpdate.unfinished)
	statePID := eventStatePID(envelope, r.targetPID)

	switch stateUpdate.kind {
	case traceStateLifecycle:
		r.handleDeferredExit(stateUpdate.deferredExit, statePID)
		r.handleLifecycle(stateUpdate)
	case traceStateSyscallEnter:
		r.handleEnter(stateUpdate, statePID)
		r.handleDeferredExit(stateUpdate.deferredExit, statePID)
	case traceStateSyscallFragment:
		return
	case traceStateSyscallExit:
		if stateUpdate.deferred {
			return
		}
		r.handleExit(stateUpdate, statePID)
	default:
		return
	}
}

func (r *TraceEventRouter) applyProcessStateInheritance(inheritance *processStateInheritance) {
	if inheritance == nil || r.lifecycle == nil {
		return
	}
	r.lifecycle.InheritProcessState(int(inheritance.parentTGID), int(inheritance.childTGID))
}

func (r *TraceEventRouter) handleUnfinished(pendingSyscalls []*pendingSyscallState) {
	if r.pipeline == nil {
		return
	}
	for _, pending := range pendingSyscalls {
		if pending == nil {
			continue
		}
		view := pending.enterView()
		ev := newSyscallEventContextFromViewWithDeps(
			r.contextDeps,
			view,
			int(pending.pid),
			nil,
			pending.payloadSections,
		)
		if !ev.shouldOutput() || !r.pipeline.HandleUnfinished(ev) {
			continue
		}
		pending.unfinishedPrinted = true
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

func (r *TraceEventRouter) handleDeferredExit(update *TraceStateUpdate, statePID int) {
	if update == nil {
		return
	}
	r.handleExit(*update, statePID)
}

func eventStatePID(envelope traceEventEnvelope, targetPID int) int {
	if envelope.valid && envelope.pid != 0 {
		return int(envelope.pid)
	}
	return targetPID
}
