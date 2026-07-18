package main

import "strace-go/pkg/handler"

type pendingSyscallState struct {
	pid             uint32
	tid             uint32
	sysID           uint32
	enterTime       uint64
	args            [6]uint64
	probeRetEnter   int32
	genericEnterRaw bool
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

type TraceState struct {
	pendingSyscalls   map[uint32]*pendingSyscallState
	pendingExecArgs   map[int]string
	suspendedSyscalls map[int]string
	tasks             map[uint32]*TaskState
}

type traceStateEventKind uint8

const (
	traceStateSyscallExit traceStateEventKind = iota
	traceStateSyscallEnter
	traceStateLifecycle
)

type TraceStateUpdate struct {
	kind            traceStateEventKind
	syscallView     syscallEventView
	lifecycleView   lifecycleEventView
	payloadSections []handler.PayloadSection
	pendingEnter    *pendingSyscallState
	lifecycleTask   *TaskState
}

func newTraceState() *TraceState {
	return &TraceState{}
}

func (s *traceSession) traceState() *TraceState {
	if s.state == nil {
		s.state = newTraceState()
	}
	return s.state
}

func (st *TraceState) handleEnvelope(envelope rawEventEnvelope) TraceStateUpdate {
	if envelope.isLifecycle() {
		lifecycleView := envelope.lifecycleView()
		task := st.applyLifecycleEvent(lifecycleView)
		if lifecycleView.action == lifecycleExit || lifecycleView.action == lifecycleFree {
			st.clearTaskPending(lifecycleView.tid)
		}
		return TraceStateUpdate{
			kind:          traceStateLifecycle,
			lifecycleView: lifecycleView,
			lifecycleTask: task,
		}
	}

	syscallView := envelope.syscallView()
	st.noteSyscallTask(syscallView)
	if syscallView.isGenericEnter() {
		st.rememberEnterEvent(syscallView, envelope.payload)
		return TraceStateUpdate{
			kind:            traceStateSyscallEnter,
			syscallView:     syscallView,
			payloadSections: envelope.payload,
		}
	}
	return TraceStateUpdate{
		kind:            traceStateSyscallExit,
		syscallView:     syscallView,
		payloadSections: envelope.payload,
		pendingEnter:    st.consumeEnterEvent(syscallView),
	}
}

func (view syscallEventView) isGenericEnter() bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagGenericEnter) != 0
}

func (view syscallEventView) isExit() bool {
	return view.eventType == bpfEventTypeExit
}

func (st *TraceState) rememberEnterEvent(view syscallEventView, payload []handler.PayloadSection) {
	if st.pendingSyscalls == nil {
		st.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	st.pendingSyscalls[view.tid] = &pendingSyscallState{
		pid:             view.pid,
		tid:             view.tid,
		sysID:           view.sysID,
		enterTime:       view.enterTime,
		args:            view.args,
		probeRetEnter:   view.probeRetEnter,
		genericEnterRaw: view.isGenericEnter(),
		payloadSections: copyPayloadSections(payload),
	}
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

func (st *TraceState) clearTaskPending(tid uint32) {
	delete(st.pendingExecArgs, int(tid))
	delete(st.suspendedSyscalls, int(tid))
	delete(st.pendingSyscalls, tid)
}
