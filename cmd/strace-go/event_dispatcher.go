package main

type TraceEventDispatcher struct {
	targetPID   int
	state       traceEventState
	lifecycle   lifecycleEventSink
	json        syscallEnterSink
	pipeline    syscallExitSink
	contextDeps syscallEventContextDeps
}

type TraceEventDispatcherDeps struct {
	TargetPID   int
	State       traceEventState
	Lifecycle   lifecycleEventSink
	JSON        syscallEnterSink
	Pipeline    syscallExitSink
	ContextDeps syscallEventContextDeps
}

func newTraceEventDispatcher(deps TraceEventDispatcherDeps) *TraceEventDispatcher {
	return &TraceEventDispatcher{
		targetPID:   deps.TargetPID,
		state:       deps.State,
		lifecycle:   deps.Lifecycle,
		json:        deps.JSON,
		pipeline:    deps.Pipeline,
		contextDeps: deps.ContextDeps,
	}
}

// Dispatch owns effects after TraceState has produced a stable update.
func (d *TraceEventDispatcher) Dispatch(envelope traceEventEnvelope, update TraceStateUpdate) {
	if d == nil || d.state == nil {
		return
	}
	d.applyProcessStateInheritance(update.processInherit)
	d.handleUnfinished(update.unfinished)
	statePID := eventStatePID(envelope, d.targetPID)

	switch update.kind {
	case traceStateLifecycle:
		d.handleDeferredExit(update.deferredExit, statePID)
		d.handleLifecycle(update)
	case traceStateSyscallEnter:
		d.handleEnter(update, statePID)
		d.handleDeferredExit(update.deferredExit, statePID)
	case traceStateSyscallFragment:
		return
	case traceStateSyscallExit:
		if !update.deferred {
			d.handleExit(update, statePID)
		}
	}
}

func (d *TraceEventDispatcher) applyProcessStateInheritance(inheritance *processStateInheritance) {
	if inheritance == nil || d.lifecycle == nil {
		return
	}
	d.lifecycle.InheritProcessState(int(inheritance.parentTGID), int(inheritance.childTGID))
}

func (d *TraceEventDispatcher) handleUnfinished(pendingSyscalls []unfinishedSyscallView) {
	if d.pipeline == nil || !d.pipeline.HasTextOutput() {
		for _, pending := range pendingSyscalls {
			d.state.markUnfinishedPrinted(pending.tid)
		}
		return
	}
	for _, pending := range pendingSyscalls {
		view := pending.enterView()
		ev := newSyscallEventContextFromViewWithDeps(
			d.contextDeps,
			view,
			int(pending.pid),
			nil,
			pending.payloadSections,
		)
		if !ev.shouldOutput() || !d.pipeline.HandleUnfinished(ev) {
			d.state.requeueUnfinished(pending.tid)
			continue
		}
		d.state.markUnfinishedPrinted(pending.tid)
	}
}

func (d *TraceEventDispatcher) handleLifecycle(update TraceStateUpdate) {
	if d.lifecycle != nil {
		d.lifecycle.Handle(update.lifecycleView, update.lifecycleTask)
	}
}

func (d *TraceEventDispatcher) handleEnter(update TraceStateUpdate, statePID int) {
	if d.json == nil {
		return
	}
	d.json.HandleEnter(newSyscallEnterEventContextFromDeps(
		d.contextDeps,
		update.syscallView,
		statePID,
		update.payloadSections,
	))
}

func (d *TraceEventDispatcher) handleExit(update TraceStateUpdate, statePID int) {
	if d.pipeline == nil {
		return
	}
	ev := newSyscallEventContextFromViewWithDeps(
		d.contextDeps,
		update.syscallView,
		statePID,
		update.pendingEnter,
		update.payloadSections,
	)
	d.pipeline.Handle(ev)
}

func (d *TraceEventDispatcher) handleDeferredExit(update *TraceStateUpdate, statePID int) {
	if update != nil {
		d.handleExit(*update, statePID)
	}
}
