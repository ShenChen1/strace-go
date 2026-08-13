package main

type TraceEventRouter struct {
	scope       TraceScope
	targetPID   int
	state       traceEventState
	lifecycle   lifecycleEventSink
	json        syscallEnterSink
	pipeline    syscallExitSink
	contextDeps syscallEventContextDeps
}

type TraceEventRouterDeps struct {
	Scope       TraceScope
	TargetPID   int
	State       traceEventState
	Lifecycle   lifecycleEventSink
	JSON        syscallEnterSink
	Pipeline    syscallExitSink
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
	defer r.state.releaseTraceStateUpdate(stateUpdate)
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

func (r *TraceEventRouter) handleUnfinished(pendingSyscalls []unfinishedSyscallView) {
	if r.pipeline == nil || !r.pipeline.HasTextOutput() {
		for _, pending := range pendingSyscalls {
			r.state.markUnfinishedPrinted(pending.tid)
		}
		return
	}
	for _, pending := range pendingSyscalls {
		view := pending.enterView()
		ev := newSyscallEventContextFromViewWithDeps(
			r.contextDeps,
			view,
			int(pending.pid),
			nil,
			pending.payloadSections,
		)
		if !ev.shouldOutput() || !r.pipeline.HandleUnfinished(ev) {
			r.state.requeueUnfinished(pending.tid)
			continue
		}
		r.state.markUnfinishedPrinted(pending.tid)
	}
}

func (r *TraceEventRouter) handleLifecycle(update TraceStateUpdate) {
	if r.lifecycle != nil {
		r.lifecycle.Handle(update.lifecycleView, update.lifecycleTask)
	}
}

func (r *TraceEventRouter) handleEnter(update TraceStateUpdate, statePID int) {
	if r.json != nil {
		r.json.HandleEnter(newSyscallEnterEventContextWithFlagDecoder(
			update.syscallView,
			statePID,
			update.payloadSections,
			r.contextDeps.catalog,
			r.contextDeps.filter,
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
