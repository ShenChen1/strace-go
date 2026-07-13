package main

import "bytes"

type pendingSyscallState struct {
	pid             uint32
	tid             uint32
	sysID           uint32
	enterTime       uint64
	args            [6]uint64
	ptr             uint64
	dataLen         uint32
	probeRetEnter   int32
	genericEnterRaw bool
}

type traceStateEventView struct {
	valid         bool
	eventVersion  uint16
	pid           uint32
	tid           uint32
	sysID         uint32
	eventType     uint16
	eventFlags    uint32
	enterTime     uint64
	args          [6]uint64
	ptr           uint64
	dataLen       uint32
	probeRetEnter int32
	snapshotText  string
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
	kind          traceStateEventKind
	view          traceStateEventView
	pendingEnter  *pendingSyscallState
	lifecycleTask *TaskState
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

func (st *TraceState) handleView(view traceStateEventView) TraceStateUpdate {
	if view.isLifecycle() {
		task := st.applyLifecycleEvent(view)
		if view.eventFlags == lifecycleExit || view.eventFlags == lifecycleFree {
			st.clearTaskPending(view.tid)
		}
		return TraceStateUpdate{kind: traceStateLifecycle, view: view, lifecycleTask: task}
	}

	st.noteSyscallTask(view)
	if view.isGenericEnter() {
		st.rememberEnterEvent(view)
		return TraceStateUpdate{kind: traceStateSyscallEnter, view: view}
	}
	return TraceStateUpdate{
		kind:         traceStateSyscallExit,
		view:         view,
		pendingEnter: st.consumeEnterEvent(view),
	}
}

func newTraceStateEventViewFromBPF(eventRaw *bpfEvent) traceStateEventView {
	if eventRaw == nil {
		return traceStateEventView{}
	}
	snapshotText := ""
	if eventRaw.EventType == bpfEventTypeLifecycle && eventRaw.EventFlags == lifecycleExec {
		snapshotText = lifecycleSnapshotString(eventRaw)
	}
	return traceStateEventView{
		valid:         true,
		eventVersion:  eventRaw.EventVersion,
		pid:           eventRaw.Pid,
		tid:           eventRaw.Tid,
		sysID:         eventRaw.SysId,
		eventType:     eventRaw.EventType,
		eventFlags:    eventRaw.EventFlags,
		enterTime:     eventRaw.EnterTime,
		args:          eventRaw.Args,
		ptr:           eventRaw.Ptr,
		dataLen:       eventRaw.DataLen,
		probeRetEnter: eventRaw.ProbeRetEnter,
		snapshotText:  snapshotText,
	}
}

func lifecycleSnapshotString(eventRaw *bpfEvent) string {
	if eventRaw.DataLen == 0 {
		return ""
	}
	n := int(eventRaw.DataLen)
	if n > len(eventRaw.StrArg) {
		n = len(eventRaw.StrArg)
	}
	data := eventRaw.StrArg[:n]
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return string(data)
}

func (view traceStateEventView) isLifecycle() bool {
	return view.eventType == bpfEventTypeLifecycle
}

func (view traceStateEventView) isGenericEnter() bool {
	return view.eventType == bpfEventTypeEnter && (view.eventFlags&bpfEventFlagGenericEnter) != 0
}

func (view traceStateEventView) isExit() bool {
	return view.eventType == bpfEventTypeExit
}

func (st *TraceState) rememberEnterEvent(view traceStateEventView) {
	if st.pendingSyscalls == nil {
		st.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	st.pendingSyscalls[view.tid] = &pendingSyscallState{
		pid:             view.pid,
		tid:             view.tid,
		sysID:           view.sysID,
		enterTime:       view.enterTime,
		args:            view.args,
		ptr:             view.ptr,
		dataLen:         view.dataLen,
		probeRetEnter:   view.probeRetEnter,
		genericEnterRaw: view.isGenericEnter(),
	}
}

func (st *TraceState) consumeEnterEvent(view traceStateEventView) *pendingSyscallState {
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
