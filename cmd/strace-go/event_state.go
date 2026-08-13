package main

import (
	"strace-go/pkg/handler"
)

type pendingSyscallState struct {
	pid               uint32
	tid               uint32
	sysID             uint32
	enterTime         uint64
	args              [6]uint64
	probeRetEnter     int32
	genericEnterRaw   bool
	unfinishedPrinted bool
	payloadSections   []handler.PayloadSection
}

// unfinishedSyscallView borrows payload data from an in-flight pending state.
// It is valid only during the synchronous router call that owns the update.
type unfinishedSyscallView struct {
	pid             uint32
	tid             uint32
	sysID           uint32
	enterTime       uint64
	args            [6]uint64
	probeRetEnter   int32
	payloadSections []handler.PayloadSection
}

func (pending *pendingSyscallState) unfinishedView() unfinishedSyscallView {
	if pending == nil {
		return unfinishedSyscallView{}
	}
	return unfinishedSyscallView{
		pid:             pending.pid,
		tid:             pending.tid,
		sysID:           pending.sysID,
		enterTime:       pending.enterTime,
		args:            pending.args,
		probeRetEnter:   pending.probeRetEnter,
		payloadSections: pending.payloadSections,
	}
}

type pendingExitState struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
}

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
}

type processStateInheritance struct {
	parentTGID uint32
	childTGID  uint32
}

type TraceState struct {
	deferUnmatchedExits bool
	trackForkIdentity   bool
	unfinishedEnabled   bool
	pendingSyscalls     map[uint32]*pendingSyscallState
	// reusablePending is owned by the single event consumer; entries are
	// returned as soon as their snapshot is detached from the state update.
	reusablePending      []*pendingSyscallState
	reusableSnapshots    []*pendingSyscallSnapshot
	reusableUnfinished   []unfinishedSyscallView
	pendingExits         map[uint32]pendingExitState
	pendingExecArgs      map[int]string
	suspendedSyscalls    map[int]string
	tasks                map[uint32]*TaskState
	pendingForks         map[uint32]pendingForkState
	unqueuedUnfinished   map[uint32]struct{}
	inFlightUnfinished   map[uint32]struct{}
	attachTargets        map[uint32]struct{}
	attachExitReader     traceAttachExitReader
	attachExitConfigured bool
}

type traceStateEventKind uint8

const (
	traceStateSyscallExit traceStateEventKind = iota
	traceStateSyscallEnter
	traceStateLifecycle
	traceStateSyscallFragment
)

type TraceStateUpdate struct {
	kind            traceStateEventKind
	deferred        bool
	syscallView     syscallEventView
	lifecycleView   lifecycleEventView
	payloadSections []handler.PayloadSection
	pendingEnter    *pendingSyscallSnapshot
	lifecycleTask   *TaskState
	processInherit  *processStateInheritance
	unfinished      []unfinishedSyscallView
	deferredExit    *TraceStateUpdate
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
	return len(st.pendingSyscalls)
}

func isTerminatingSyscall(view syscallEventView) bool {
	name := syscallMeta(view.sysID).Name
	return name == "exit" || name == "exit_group"
}

func (pending *pendingSyscallState) enterView() syscallEventView {
	return syscallEventView{
		valid:         true,
		pid:           pending.pid,
		tid:           pending.tid,
		sysID:         pending.sysID,
		eventType:     bpfEventTypeEnter,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          pending.args,
		enterTime:     pending.enterTime,
		probeRetEnter: pending.probeRetEnter,
	}
}

func (view unfinishedSyscallView) enterView() syscallEventView {
	return syscallEventView{
		valid:         true,
		pid:           view.pid,
		tid:           view.tid,
		sysID:         view.sysID,
		eventType:     bpfEventTypeEnter,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          view.args,
		enterTime:     view.enterTime,
		probeRetEnter: view.probeRetEnter,
	}
}

func (view syscallEventView) isGenericEnter() bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagGenericEnter) != 0
}

func (view syscallEventView) isExit() bool {
	return view.eventType == bpfEventTypeExit
}

func (view syscallEventView) isExitFragment() bool {
	return view.isExit() && (view.eventFlags&bpfEventFlagExitFragment) != 0
}

func (st *TraceState) rememberEnterEvent(view syscallEventView, payload []handler.PayloadSection) {
	if st.pendingSyscalls == nil {
		st.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	if pending := st.pendingSyscalls[view.tid]; pending != nil && pending.sysID == view.sysID {
		pending.genericEnterRaw = pending.genericEnterRaw || view.isGenericEnter()
		pending.unfinishedPrinted = pending.unfinishedPrinted || view.probeRetEnter >= 2
		pending.payloadSections = mergeEnterPayloadSections(pending.payloadSections, payload)
		return
	}
	if pending := st.pendingSyscalls[view.tid]; pending != nil {
		delete(st.pendingSyscalls, view.tid)
		st.releasePendingSyscall(pending)
	}
	st.deleteUnfinishedCandidate(view.tid)
	pending := st.acquirePendingSyscall()
	*pending = pendingSyscallState{
		pid:               view.pid,
		tid:               view.tid,
		sysID:             view.sysID,
		enterTime:         view.enterTime,
		args:              view.args,
		probeRetEnter:     view.probeRetEnter,
		genericEnterRaw:   view.isGenericEnter(),
		unfinishedPrinted: view.probeRetEnter >= 2,
		payloadSections:   copyPayloadSections(payload),
	}
	st.pendingSyscalls[view.tid] = pending
	st.enqueueUnfinished(view.tid)
}

func (st *TraceState) acquirePendingSyscall() *pendingSyscallState {
	last := len(st.reusablePending) - 1
	if last < 0 {
		return &pendingSyscallState{}
	}
	pending := st.reusablePending[last]
	st.reusablePending = st.reusablePending[:last]
	return pending
}

func (st *TraceState) releasePendingSyscall(pending *pendingSyscallState) {
	if st == nil || pending == nil {
		return
	}
	*pending = pendingSyscallState{}
	st.reusablePending = append(st.reusablePending, pending)
}

// releaseTraceStateUpdate returns snapshots after all output side effects for
// the update, including one deferred exit, have completed.
func (st *TraceState) releaseTraceStateUpdate(update TraceStateUpdate) {
	if st == nil {
		return
	}
	if update.unfinished != nil {
		clear(update.unfinished)
		st.reusableUnfinished = update.unfinished[:0]
	}
	st.releasePendingSnapshot(update.pendingEnter)
	if update.deferredExit != nil {
		st.releasePendingSnapshot(update.deferredExit.pendingEnter)
	}
}

func (st *TraceState) rememberExitFragment(view syscallEventView, payload []handler.PayloadSection) {
	if st.pendingSyscalls == nil {
		return
	}
	pending := st.pendingSyscalls[view.tid]
	if pending == nil || pending.sysID != view.sysID {
		return
	}
	pending.payloadSections = mergeEnterPayloadSections(pending.payloadSections, payload)
}

func (st *TraceState) rememberPendingExit(view syscallEventView, payload []handler.PayloadSection) {
	if st.pendingExits == nil {
		st.pendingExits = make(map[uint32]pendingExitState)
	}
	st.pendingExits[view.tid] = pendingExitState{
		view:            view,
		payloadSections: copyPayloadSections(payload),
	}
}

func (st *TraceState) takePendingExit(view syscallEventView) (pendingExitState, bool) {
	pending, ok := st.takePendingExitForTID(view.tid)
	if !ok || pending.view.sysID != view.sysID || pending.view.enterTime != view.enterTime {
		return pendingExitState{}, false
	}
	return pending, true
}

func (st *TraceState) takePendingExitForTID(tid uint32) (pendingExitState, bool) {
	if st.pendingExits == nil {
		return pendingExitState{}, false
	}
	pending, ok := st.pendingExits[tid]
	delete(st.pendingExits, tid)
	return pending, ok
}

func mergeEnterPayloadSections(existing []handler.PayloadSection, next []handler.PayloadSection) []handler.PayloadSection {
	merged := existing
	for _, section := range next {
		if hasEquivalentPayloadSection(merged, section) {
			continue
		}
		merged = appendOwnedPayloadSection(merged, section)
	}
	return merged
}

func appendOwnedPayloadSection(owned []handler.PayloadSection, borrowed handler.PayloadSection) []handler.PayloadSection {
	copied := borrowed
	if len(borrowed.Data) > 0 {
		copied.Data = append([]byte(nil), borrowed.Data...)
	}
	return append(owned, copied)
}

func copyPayloadSections(sections []handler.PayloadSection) []handler.PayloadSection {
	if len(sections) == 0 {
		return nil
	}
	out := make([]handler.PayloadSection, len(sections))
	for i, section := range sections {
		out[i] = section
		if len(section.Data) > 0 {
			out[i].Data = append([]byte(nil), section.Data...)
		}
	}
	return out
}

func (st *TraceState) consumeEnterEvent(view syscallEventView) *pendingSyscallSnapshot {
	if !view.isExit() || st.pendingSyscalls == nil {
		return nil
	}
	pending := st.pendingSyscalls[view.tid]
	delete(st.pendingSyscalls, view.tid)
	st.deleteUnfinishedCandidate(view.tid)
	if pending == nil {
		return nil
	}
	if pending.sysID != view.sysID {
		st.releasePendingSyscall(pending)
		return nil
	}
	// Detach the payload owner before returning the detached transfer view. The
	// state owner can now be reused by the next event on this TID.
	snapshot := st.acquirePendingSnapshot(pending)
	st.releasePendingSyscall(pending)
	return snapshot
}

func (st *TraceState) rememberPendingExecArgs(tid int, argLine string) {
	if st.pendingExecArgs == nil {
		st.pendingExecArgs = make(map[int]string)
	}
	st.pendingExecArgs[tid] = argLine
}

func (st *TraceState) takePendingExecArgs(tid int) (string, bool) {
	argLine, ok := st.pendingExecArgs[tid]
	delete(st.pendingExecArgs, tid)
	return argLine, ok
}

func (st *TraceState) pendingExecArgsFor(tid int) (string, bool) {
	argLine, ok := st.pendingExecArgs[tid]
	return argLine, ok
}

func (st *TraceState) deletePendingExecArgs(tid int) {
	delete(st.pendingExecArgs, tid)
}

func (st *TraceState) rememberSuspendedSyscall(tid int, name string) {
	if st.suspendedSyscalls == nil {
		st.suspendedSyscalls = make(map[int]string)
	}
	st.suspendedSyscalls[tid] = name
}

func (st *TraceState) deleteSuspendedSyscall(tid int) {
	delete(st.suspendedSyscalls, tid)
}

func (st *TraceState) consumeSuspendedSyscall(tid int) bool {
	if st.suspendedSyscalls == nil {
		return false
	}
	_, ok := st.suspendedSyscalls[tid]
	if ok {
		delete(st.suspendedSyscalls, tid)
	}
	return ok
}

func (st *TraceState) markUnfinishedPrinted(tid uint32) {
	pending := st.pendingSyscalls[tid]
	st.deleteUnfinishedCandidate(tid)
	if pending != nil {
		pending.unfinishedPrinted = true
	}
}

func (st *TraceState) clearTaskPending(tid uint32) {
	st.deleteUnfinishedCandidate(tid)
	delete(st.pendingExecArgs, int(tid))
	delete(st.suspendedSyscalls, int(tid))
	if pending := st.pendingSyscalls[tid]; pending != nil {
		delete(st.pendingSyscalls, tid)
		st.releasePendingSyscall(pending)
	}
	delete(st.pendingExits, tid)
	delete(st.pendingForks, tid)
}

func (st *TraceState) retireTask(tid uint32) {
	if tid == 0 {
		return
	}
	st.clearTaskPending(tid)
	delete(st.tasks, tid)
}
