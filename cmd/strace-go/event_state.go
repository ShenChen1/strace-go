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

func (s *traceSession) rememberEnterEvent(eventRaw *bpfEvent) {
	if s.pendingSyscalls == nil {
		s.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	s.pendingSyscalls[eventRaw.Tid] = &pendingSyscallState{
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

func (s *traceSession) consumeEnterEvent(eventRaw *bpfEvent) *pendingSyscallState {
	if !isExitEvent(eventRaw) || s.pendingSyscalls == nil {
		return nil
	}
	pending := s.pendingSyscalls[eventRaw.Tid]
	delete(s.pendingSyscalls, eventRaw.Tid)
	if pending == nil || pending.sysID != eventRaw.SysId {
		return nil
	}
	return pending
}

func isExitEvent(eventRaw *bpfEvent) bool {
	return eventRaw.EventType == bpfEventTypeExit
}

func (s *traceSession) rememberPendingExecArgs(tid int, argLine string) {
	if s.pendingExecArgs == nil {
		s.pendingExecArgs = make(map[int]string)
	}
	s.pendingExecArgs[tid] = argLine
}

func (s *traceSession) takePendingExecArgs(tid int) (string, bool) {
	argLine, ok := s.pendingExecArgs[tid]
	delete(s.pendingExecArgs, tid)
	return argLine, ok
}

func (s *traceSession) pendingExecArgsFor(tid int) (string, bool) {
	argLine, ok := s.pendingExecArgs[tid]
	return argLine, ok
}

func (s *traceSession) deletePendingExecArgs(tid int) {
	delete(s.pendingExecArgs, tid)
}

func (s *traceSession) rememberSuspendedSyscall(tid int, name string) {
	if s.suspendedSyscalls == nil {
		s.suspendedSyscalls = make(map[int]string)
	}
	s.suspendedSyscalls[tid] = name
}

func (s *traceSession) deleteSuspendedSyscall(tid int) {
	delete(s.suspendedSyscalls, tid)
}

func (s *traceSession) consumeSuspendedSyscall(tid int) bool {
	if s.suspendedSyscalls == nil {
		return false
	}
	_, ok := s.suspendedSyscalls[tid]
	if ok {
		delete(s.suspendedSyscalls, tid)
	}
	return ok
}
