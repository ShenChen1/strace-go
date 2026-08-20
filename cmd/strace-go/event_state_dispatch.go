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
	syscallView := envelope.syscallView()
	processInherit := st.resolveForkIdentity(syscallView.tid, syscallView.pid)
	if syscallView.isGenericEnter() {
		st.noteSyscallTask(syscallView)
		return st.handleSyscallEnter(syscallView, envelope.payload, processInherit, unfinished)
	}
	if syscallView.isExitFragment() {
		st.noteSyscallTask(syscallView)
		return st.handleSyscallFragment(syscallView, envelope.payload, processInherit, unfinished)
	}
	return st.handleSyscallExit(syscallView, envelope.payload, processInherit, unfinished)
}

func (st *TraceState) handleSyscallEnter(view syscallEventView, payload []handler.PayloadSection, processInherit *processStateInheritance, unfinished []unfinishedSyscallView) TraceStateUpdate {
	st.rememberEnterEvent(view, payload)
	update := TraceStateUpdate{
		kind:            traceStateSyscallEnter,
		syscallView:     view,
		payloadSections: payload,
		processInherit:  processInherit,
		unfinished:      unfinished,
	}
	if pendingExit, ok := st.takePendingExit(view); ok {
		st.attachDeferredExit(&update, pendingExit)
	}
	return update
}

func (st *TraceState) attachDeferredExit(update *TraceStateUpdate, pendingExit pendingExitState) {
	pendingEnter := st.consumeEnterEvent(pendingExit.view)
	if pendingEnter == nil {
		return
	}
	if st.isTerminatingSyscall(pendingExit.view) {
		st.markAttachTargetTerminated(pendingExit.view)
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

func (st *TraceState) handleSyscallFragment(view syscallEventView, payload []handler.PayloadSection, processInherit *processStateInheritance, unfinished []unfinishedSyscallView) TraceStateUpdate {
	st.rememberExitFragment(view, payload)
	return TraceStateUpdate{
		kind:            traceStateSyscallFragment,
		syscallView:     view,
		payloadSections: payload,
		processInherit:  processInherit,
		unfinished:      unfinished,
	}
}

func (st *TraceState) handleSyscallExit(view syscallEventView, payload []handler.PayloadSection, processInherit *processStateInheritance, unfinished []unfinishedSyscallView) TraceStateUpdate {
	pendingEnter := st.consumeEnterEvent(view)
	if pendingEnter == nil {
		st.noteSyscallTask(view)
	}
	if pendingEnter == nil && st.deferUnmatchedExits {
		st.rememberPendingExit(view, payload)
		return TraceStateUpdate{
			kind:            traceStateSyscallExit,
			deferred:        true,
			syscallView:     view,
			payloadSections: payload,
			processInherit:  processInherit,
			unfinished:      unfinished,
		}
	}
	if st.isTerminatingSyscall(view) {
		st.markAttachTargetTerminated(view)
		st.markLifecyclePending(view.tid)
		st.clearTaskPending(view.tid)
	}
	return TraceStateUpdate{
		kind:            traceStateSyscallExit,
		syscallView:     view,
		payloadSections: payload,
		pendingEnter:    pendingEnter,
		processInherit:  processInherit,
		unfinished:      unfinished,
	}
}
