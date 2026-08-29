package main

import "strace-go/pkg/handler"

type lifecycleEventView struct {
	valid        bool
	eventVersion uint16
	eventType    uint16
	eventFlags   uint32
	action       uint32
	pid          uint32
	tid          uint32
	args         [6]uint64
	enterTime    uint64
	snapshotText string
	comm         string
}

type processStateInheritance struct {
	parentTGID uint32
	childTGID  uint32
}

type traceDeferredExit struct {
	valid           bool
	syscallView     syscallEventView
	payloadStorage  *tracePayloadStorage
	payloadSections []handler.PayloadSection
	pendingEnter    *pendingSyscallSnapshot
}

type TraceState struct {
	deferUnmatchedExits        bool
	elidePlainEnter            bool
	elideNonBlockingPlainEnter bool
	lifecycleIDs               syscallLifecycleIDs
	correlation                traceSyscallCorrelationState
	unfinished                 traceUnfinishedState
	lifecycle                  traceTaskLifecycleState
	attach                     traceAttachState
}

type traceStateEventKind uint8

const (
	traceStateSyscallExit traceStateEventKind = iota
	traceStateSyscallEnter
	traceStateLifecycle
	traceStateSignal
	traceStateSyscallFragment
)

type TraceStateUpdate struct {
	kind            traceStateEventKind
	deferred        bool
	syscallView     syscallEventView
	lifecycleView   lifecycleEventView
	signalView      signalEventView
	payloadSections []handler.PayloadSection
	pendingEnter    *pendingSyscallSnapshot
	lifecycleTask   *TaskState
	processInherit  *processStateInheritance
	unfinished      []unfinishedSyscallView
	deferredExit    traceDeferredExit
}

func (s *traceSession) traceState() traceStateOwner {
	if s == nil {
		return nil
	}
	return s.dependencies.State
}

// PendingStaleCount reports unconsumed syscall enters at finalization time.
// The single event consumer owns the map, so this read needs no lock.
func (st *TraceState) PendingStaleCount() int {
	if st == nil {
		return 0
	}
	return st.correlation.pendingCount()
}

func isTerminatingSyscall(view *syscallEventView) bool {
	name := syscallMeta(view.sysID).Name
	return name == "exit" || name == "exit_group"
}

func (st *TraceState) isTerminatingSyscall(view *syscallEventView) bool {
	if st == nil || !st.lifecycleIDs.configured() {
		return isTerminatingSyscall(view)
	}
	return st.lifecycleIDs.isTerminating(view.sysID)
}

func isGenericEnterView(view *syscallEventView) bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagGenericEnter) != 0
}

func isEnterFragmentView(view *syscallEventView) bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagEnterFragment) != 0
}

func isExitView(view *syscallEventView) bool {
	return view.eventType == bpfEventTypeExit
}

func isExitFragmentView(view *syscallEventView) bool {
	return isExitView(view) && (view.eventFlags&bpfEventFlagExitFragment) != 0
}

func (view syscallEventView) isGenericEnter() bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagGenericEnter) != 0
}

func (view syscallEventView) isEnterFragment() bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagEnterFragment) != 0
}

func (view syscallEventView) isExit() bool {
	return view.eventType == bpfEventTypeExit
}

func (view syscallEventView) isExitFragment() bool {
	return view.isExit() && (view.eventFlags&bpfEventFlagExitFragment) != 0
}

func (st *TraceState) rememberEnterEvent(view *syscallEventView, payload []handler.PayloadSection) {
	if !st.correlation.rememberEnterEvent(view, payload) {
		return
	}
	st.unfinished.deleteCandidate(view.tid)
	st.unfinished.enqueue(view.tid, view.sysID)
}

func (st *TraceState) releaseTraceStateUpdate(update TraceStateUpdate) {
	if st == nil {
		return
	}
	st.unfinished.releaseViews(update.unfinished)
	st.releaseTraceStateUpdateResources(&update)
}

func (st *TraceState) releaseTraceStateUpdateResources(update *TraceStateUpdate) {
	if st == nil || update == nil {
		return
	}
	st.correlation.releasePendingSnapshot(update.pendingEnter)
	if update.deferredExit.valid {
		st.correlation.releasePendingSnapshot(update.deferredExit.pendingEnter)
		st.correlation.releasePayloadStorage(update.deferredExit.payloadStorage)
	}
}

func (st *TraceState) rememberPayloadFragment(view syscallEventView, payload []handler.PayloadSection) {
	st.correlation.rememberPayloadFragment(view, payload)
}

func (st *TraceState) rememberPendingExit(view *syscallEventView, payload []handler.PayloadSection) {
	st.correlation.rememberPendingExit(view, payload)
}

func (st *TraceState) takePendingExit(view *syscallEventView) (pendingExitState, bool) {
	return st.correlation.takePendingExit(view)
}

func (st *TraceState) takePendingExitForTID(tid uint32) (pendingExitState, bool) {
	return st.correlation.takePendingExitForTID(tid)
}

func (st *TraceState) consumeEnterEvent(view *syscallEventView) *pendingSyscallSnapshot {
	snapshot := st.correlation.consumeEnterEvent(view)
	if view != nil {
		st.unfinished.deleteCandidate(view.tid)
	}
	return snapshot
}

func (st *TraceState) synthesizeGenericEnter(view *syscallEventView) *pendingSyscallSnapshot {
	return st.correlation.synthesizeGenericEnter(view)
}

func (st *TraceState) rememberPendingExecArgs(tid int, argLine string) {
	st.correlation.rememberPendingExecArgs(tid, argLine)
}

func (st *TraceState) takePendingExecArgs(tid int) (string, bool) {
	return st.correlation.takePendingExecArgs(tid)
}

func (st *TraceState) pendingExecArgsFor(tid int) (string, bool) {
	return st.correlation.pendingExecArgsFor(tid)
}

func (st *TraceState) deletePendingExecArgs(tid int) {
	st.correlation.deletePendingExecArgs(tid)
}

func (st *TraceState) rememberSuspendedSyscall(tid int, name string) {
	st.correlation.rememberSuspendedSyscall(tid, name)
}

func (st *TraceState) deleteSuspendedSyscall(tid int) {
	st.correlation.deleteSuspendedSyscall(tid)
}

func (st *TraceState) consumeSuspendedSyscall(tid int) bool {
	return st.correlation.consumeSuspendedSyscall(tid)
}

func (st *TraceState) markUnfinishedPrinted(tid uint32) {
	st.correlation.markUnfinishedPrinted(tid)
	st.unfinished.deleteCandidate(tid)
}

func (st *TraceState) setUnfinishedEnabled(enabled bool) {
	if st == nil {
		return
	}
	st.unfinished.setEnabled(enabled, &st.correlation)
}

func (st *TraceState) pendingForOtherTID(tid uint32) []unfinishedSyscallView {
	if st == nil {
		return nil
	}
	return st.unfinished.pendingForOtherTID(tid, &st.correlation)
}

func (st *TraceState) requeueUnfinished(tid uint32) {
	if st == nil {
		return
	}
	st.unfinished.requeue(tid, &st.correlation)
}
