package main

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

type TraceState struct {
	pendingSyscalls   map[uint32]*pendingSyscallState
	pendingExecArgs   map[int]string
	suspendedSyscalls map[int]string
	tasks             map[uint32]*TaskState
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

func (st *TraceState) rememberEnterEvent(eventRaw *bpfEvent) {
	if st.pendingSyscalls == nil {
		st.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	st.pendingSyscalls[eventRaw.Tid] = &pendingSyscallState{
		pid:             eventRaw.Pid,
		tid:             eventRaw.Tid,
		sysID:           eventRaw.SysId,
		enterTime:       eventRaw.EnterTime,
		args:            eventRaw.Args,
		ptr:             eventRaw.Ptr,
		dataLen:         eventRaw.DataLen,
		probeRetEnter:   eventRaw.ProbeRetEnter,
		genericEnterRaw: isGenericEnterEvent(eventRaw),
	}
}

func (st *TraceState) consumeEnterEvent(eventRaw *bpfEvent) *pendingSyscallState {
	if !isExitEvent(eventRaw) || st.pendingSyscalls == nil {
		return nil
	}
	pending := st.pendingSyscalls[eventRaw.Tid]
	delete(st.pendingSyscalls, eventRaw.Tid)
	if pending == nil || pending.sysID != eventRaw.SysId {
		return nil
	}
	return pending
}

func isExitEvent(eventRaw *bpfEvent) bool {
	return eventRaw.EventType == bpfEventTypeExit
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
