package main

import "strace-go/pkg/handler"

func (st *TraceState) handleEnvelope(envelope traceEventEnvelope) TraceStateUpdate {
	unfinished := st.pendingForOtherTID(envelope.tid)
	if envelope.isLifecycle() {
		return st.handleLifecycleEnvelope(envelope, unfinished)
	}
	return st.handleSyscallEnvelope(envelope, unfinished)
}

func (st *TraceState) handleLifecycleEnvelope(envelope traceEventEnvelope, unfinished []unfinishedSyscallView) TraceStateUpdate {
	lifecycleView := envelope.lifecycleView()
	task, processInherit := st.applyLifecycleEvent(lifecycleView)
	update := TraceStateUpdate{
		kind:           traceStateLifecycle,
		lifecycleView:  lifecycleView,
		lifecycleTask:  snapshotTaskState(task),
		processInherit: processInherit,
		unfinished:     unfinished,
	}
	if lifecycleView.action != lifecycleExit && lifecycleView.action != lifecycleFree {
		return update
	}

	st.rememberLifecycleExit(lifecycleView.pid, lifecycleView.tid)
	st.clearLifecyclePending(lifecycleView.tid)
	st.markAttachTargetExited(lifecycleView.pid, lifecycleView.tid)
	if pendingExit, ok := st.takePendingExitForTID(lifecycleView.tid); ok {
		update.deferredExit = &TraceStateUpdate{
			kind:            traceStateSyscallExit,
			syscallView:     pendingExit.view,
			payloadSections: pendingExit.payloadSections,
		}
	}
	st.retireTask(lifecycleView.tid)
	return update
}

func (st *TraceState) handleSyscallEnvelope(envelope traceEventEnvelope, unfinished []unfinishedSyscallView) TraceStateUpdate {
	update := TraceStateUpdate{
		syscallView: envelope.syscallView(),
		unfinished:  unfinished,
	}
	syscallView := &update.syscallView
	update.processInherit = st.resolveForkIdentity(syscallView.tid, syscallView.pid)
	if isGenericEnterView(syscallView) {
		st.noteSyscallTask(syscallView)
		st.handleSyscallEnter(&update, envelope.payload)
		return update
	}
	if isExitFragmentView(syscallView) {
		st.noteSyscallTask(syscallView)
		st.handleSyscallFragment(&update, envelope.payload)
		return update
	}
	st.handleSyscallExit(&update, envelope.payload)
	return update
}

func (st *TraceState) handleSyscallEnter(update *TraceStateUpdate, payload []handler.PayloadSection) {
	view := &update.syscallView
	st.rememberEnterEvent(view, payload)
	update.kind = traceStateSyscallEnter
	update.payloadSections = payload
	if pendingExit, ok := st.takePendingExit(view); ok {
		st.attachDeferredExit(update, pendingExit)
	}
}

func (st *TraceState) attachDeferredExit(update *TraceStateUpdate, pendingExit pendingExitState) {
	pendingEnter := st.consumeEnterEvent(&pendingExit.view)
	if pendingEnter == nil {
		return
	}
	if st.isTerminatingSyscall(&pendingExit.view) {
		st.markAttachTargetTerminated(&pendingExit.view)
		st.markLifecyclePending(pendingExit.view.tid)
		st.clearTaskPending(pendingExit.view.tid)
	}
	update.deferredExit = &TraceStateUpdate{
		kind:            traceStateSyscallExit,
		syscallView:     pendingExit.view,
		payloadSections: pendingExit.payloadSections,
		pendingEnter:    pendingEnter,
	}
}

func (st *TraceState) handleSyscallFragment(update *TraceStateUpdate, payload []handler.PayloadSection) {
	st.rememberExitFragment(update.syscallView, payload)
	update.kind = traceStateSyscallFragment
	update.payloadSections = payload
}

func (st *TraceState) handleSyscallExit(update *TraceStateUpdate, payload []handler.PayloadSection) {
	view := &update.syscallView
	pendingEnter := st.consumeEnterEvent(view)
	if pendingEnter == nil {
		st.noteSyscallTask(view)
	}
	if pendingEnter == nil && st.deferUnmatchedExits {
		st.rememberPendingExit(view, payload)
		update.kind = traceStateSyscallExit
		update.deferred = true
		update.payloadSections = payload
		return
	}
	if st.isTerminatingSyscall(view) {
		st.markAttachTargetTerminated(view)
		st.markLifecyclePending(view.tid)
		st.clearTaskPending(view.tid)
	}
	update.kind = traceStateSyscallExit
	update.payloadSections = payload
	update.pendingEnter = pendingEnter
}
