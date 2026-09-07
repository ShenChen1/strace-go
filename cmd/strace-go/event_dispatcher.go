package main

type TraceEventDispatcher struct {
	targetPID    int
	state        traceEventState
	lifecycle    lifecycleEventSink
	signal       signalEventSink
	json         syscallEnterSink
	runtimeDebug traceRuntimeDebugObserver
	pipeline     syscallExitSink
	syscallLimit traceSyscallLimitObserver
	detachOnExec traceDetachOnExecveObserver
	commObserver traceTaskCommObserver
	contextDeps  syscallEventContextDeps
	eventPolicy  traceEventOutputPolicy
}

type TraceEventDispatcherDeps struct {
	TargetPID      int
	State          traceEventState
	Lifecycle      lifecycleEventSink
	Signal         signalEventSink
	JSON           syscallEnterSink
	RuntimeDebug   traceRuntimeDebugObserver
	Pipeline       syscallExitSink
	SyscallLimit   traceSyscallLimitObserver
	DetachOnExecve traceDetachOnExecveObserver
	CommObserver   traceTaskCommObserver
	ContextDeps    syscallEventContextDeps
	EventPolicy    traceEventOutputPolicy
}

func newTraceEventDispatcher(deps TraceEventDispatcherDeps) *TraceEventDispatcher {
	return &TraceEventDispatcher{
		targetPID:    deps.TargetPID,
		state:        deps.State,
		lifecycle:    deps.Lifecycle,
		signal:       deps.Signal,
		json:         deps.JSON,
		runtimeDebug: deps.RuntimeDebug,
		pipeline:     deps.Pipeline,
		syscallLimit: deps.SyscallLimit,
		detachOnExec: deps.DetachOnExecve,
		commObserver: deps.CommObserver,
		contextDeps:  deps.ContextDeps,
		eventPolicy:  deps.EventPolicy,
	}
}

// Dispatch owns effects after TraceState has produced a stable update.
func (d *TraceEventDispatcher) Dispatch(envelope traceEventEnvelope, update TraceStateUpdate) {
	if d == nil || d.state == nil {
		return
	}
	if d.commObserver != nil && envelope.comm != "" {
		d.commObserver.ObserveTaskComm(envelope.tid, envelope.comm)
	}
	d.applyProcessStateInheritance(update.processInherit)
	d.handleUnfinished(update.unfinished)
	statePID := eventStatePID(envelope, d.targetPID)

	switch update.kind {
	case traceStateLifecycle:
		d.handleDeferredExit(update.deferredExit, statePID)
		d.handleLifecycle(update)
	case traceStateSignal:
		if d.signal != nil {
			d.signal.HandleSignal(update.signalView)
		}
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
	if d.detachOnExec != nil {
		d.detachOnExec.ObserveLifecycle(update.lifecycleView)
	}
	if d.lifecycle != nil {
		d.lifecycle.Handle(update.lifecycleView, update.lifecycleTask)
	}
}

func (d *TraceEventDispatcher) handleEnter(update TraceStateUpdate, statePID int) {
	if d.runtimeDebug != nil {
		d.runtimeDebug.Observe(update.syscallView)
	}
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
	if d.pipeline == nil && d.syscallLimit == nil && !d.detachOnExecEnabled() {
		return
	}
	ev := newSyscallEventContextFromViewWithDeps(
		d.contextDeps,
		update.syscallView,
		statePID,
		update.pendingEnter,
		update.payloadSections,
	)
	ev = ev.withNonLeaderExecDetachedStatus(d.eventPolicy)
	if d.detachOnExec != nil {
		ev = d.detachOnExec.Observe(ev)
	}
	if d.syscallLimit != nil {
		d.syscallLimit.Observe(ev)
	}
	if d.pipeline != nil {
		d.pipeline.Handle(ev)
		return
	}
	ev.releaseHandlerContext()
}

func (d *TraceEventDispatcher) detachOnExecEnabled() bool {
	return d != nil && d.detachOnExec != nil && d.detachOnExec.Enabled()
}

func (d *TraceEventDispatcher) handleDeferredExit(update traceDeferredExit, statePID int) {
	if !update.valid {
		return
	}
	d.handleExit(TraceStateUpdate{
		kind:            traceStateSyscallExit,
		syscallView:     update.syscallView,
		payloadSections: update.payloadSections,
		pendingEnter:    update.pendingEnter,
	}, statePID)
}
