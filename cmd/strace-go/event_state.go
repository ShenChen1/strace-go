package main

import (
	"sort"

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
	pendingSyscalls     map[uint32]*pendingSyscallState
	pendingExits        map[uint32]pendingExitState
	pendingExecArgs     map[int]string
	suspendedSyscalls   map[int]string
	tasks               map[uint32]*TaskState
	pendingForks        map[uint32]pendingForkState
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
	pendingEnter    *pendingSyscallState
	lifecycleTask   *TaskState
	processInherit  *processStateInheritance
	unfinished      []pendingSyscallState
	deferredExit    *TraceStateUpdate
}

func newTraceState() *TraceState {
	return &TraceState{trackForkIdentity: true}
}

func newTraceStateWithDeferredExit(enabled bool) *TraceState {
	return &TraceState{deferUnmatchedExits: enabled, trackForkIdentity: true}
}

func (s *traceSession) traceState() *TraceState {
	if s.state == nil {
		s.state = newTraceState()
	}
	return s.state
}

func (st *TraceState) handleEnvelope(envelope traceEventEnvelope) TraceStateUpdate {
	unfinished := st.pendingForOtherTID(envelope.tid)
	if envelope.isLifecycle() {
		lifecycleView := envelope.lifecycleView()
		task, processInherit := st.applyLifecycleEvent(lifecycleView)
		lifecycleTask := snapshotTaskState(task)
		var deferredExit *TraceStateUpdate
		if lifecycleView.action == lifecycleExit || lifecycleView.action == lifecycleFree {
			if pendingExit, ok := st.takePendingExitForTID(lifecycleView.tid); ok {
				deferredExit = &TraceStateUpdate{
					kind:            traceStateSyscallExit,
					syscallView:     pendingExit.view,
					payloadSections: pendingExit.payloadSections,
				}
			}
			st.retireTask(lifecycleView.tid)
		}
		return TraceStateUpdate{
			kind:           traceStateLifecycle,
			lifecycleView:  lifecycleView,
			lifecycleTask:  lifecycleTask,
			processInherit: processInherit,
			unfinished:     unfinished,
			deferredExit:   deferredExit,
		}
	}

	syscallView := envelope.syscallView()
	processInherit := st.resolveForkIdentity(syscallView.tid, syscallView.pid)
	st.noteSyscallTask(syscallView)
	if syscallView.isGenericEnter() {
		st.rememberEnterEvent(syscallView, envelope.payload)
		update := TraceStateUpdate{
			kind:            traceStateSyscallEnter,
			syscallView:     syscallView,
			payloadSections: envelope.payload,
			processInherit:  processInherit,
			unfinished:      unfinished,
		}
		if pendingExit, ok := st.takePendingExit(syscallView); ok {
			pendingEnter := st.consumeEnterEvent(pendingExit.view)
			if pendingEnter != nil {
				if isTerminatingSyscall(pendingExit.view) {
					st.retireTask(pendingExit.view.tid)
				}
				update.deferredExit = &TraceStateUpdate{
					kind:            traceStateSyscallExit,
					syscallView:     pendingExit.view,
					payloadSections: pendingExit.payloadSections,
					pendingEnter:    pendingEnter,
				}
			}
		}
		return update
	}
	if syscallView.isExitFragment() {
		st.rememberExitFragment(syscallView, envelope.payload)
		return TraceStateUpdate{
			kind:            traceStateSyscallFragment,
			syscallView:     syscallView,
			payloadSections: envelope.payload,
			processInherit:  processInherit,
			unfinished:      unfinished,
		}
	}
	pendingEnter := st.consumeEnterEvent(syscallView)
	if pendingEnter == nil && st.deferUnmatchedExits {
		st.rememberPendingExit(syscallView, envelope.payload)
		return TraceStateUpdate{
			kind:            traceStateSyscallExit,
			deferred:        true,
			syscallView:     syscallView,
			payloadSections: envelope.payload,
			processInherit:  processInherit,
			unfinished:      unfinished,
		}
	}
	if isTerminatingSyscall(syscallView) {
		st.retireTask(syscallView.tid)
	}
	return TraceStateUpdate{
		kind:            traceStateSyscallExit,
		syscallView:     syscallView,
		payloadSections: envelope.payload,
		pendingEnter:    pendingEnter,
		processInherit:  processInherit,
		unfinished:      unfinished,
	}
}

func isTerminatingSyscall(view syscallEventView) bool {
	name := syscallMeta(view.sysID).Name
	return name == "exit" || name == "exit_group"
}

func (st *TraceState) pendingForOtherTID(tid uint32) []pendingSyscallState {
	if tid == 0 || len(st.pendingSyscalls) == 0 {
		return nil
	}
	candidates := make([]pendingSyscallState, 0, len(st.pendingSyscalls))
	for pendingTID, pending := range st.pendingSyscalls {
		if pendingTID == tid || pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 {
			continue
		}
		candidates = append(candidates, copyPendingSyscallState(*pending))
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].enterTime != candidates[j].enterTime {
			return candidates[i].enterTime < candidates[j].enterTime
		}
		return candidates[i].tid < candidates[j].tid
	})
	return candidates
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
	st.pendingSyscalls[view.tid] = &pendingSyscallState{
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

func (st *TraceState) consumeEnterEvent(view syscallEventView) *pendingSyscallState {
	if !view.isExit() || st.pendingSyscalls == nil {
		return nil
	}
	pending := st.pendingSyscalls[view.tid]
	delete(st.pendingSyscalls, view.tid)
	if pending == nil || pending.sysID != view.sysID {
		return nil
	}
	// The map entry is deleted above, so its owned payload can transfer to the
	// exit update without another copy.
	return pending
}

func copyPendingSyscallState(pending pendingSyscallState) pendingSyscallState {
	pending.payloadSections = copyPayloadSections(pending.payloadSections)
	return pending
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
	if pending != nil {
		pending.unfinishedPrinted = true
	}
}

func (st *TraceState) clearTaskPending(tid uint32) {
	delete(st.pendingExecArgs, int(tid))
	delete(st.suspendedSyscalls, int(tid))
	delete(st.pendingSyscalls, tid)
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
