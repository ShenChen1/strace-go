package main

func newSyscallEventViewFromBPF(eventRaw *bpfEvent) syscallEventView {
	if eventRaw == nil {
		return syscallEventView{}
	}
	return syscallEventView{
		valid:         true,
		eventVersion:  eventRaw.EventVersion,
		pid:           eventRaw.Pid,
		tid:           eventRaw.Tid,
		sysID:         eventRaw.SysId,
		eventType:     eventRaw.EventType,
		eventFlags:    eventRaw.EventFlags,
		args:          eventRaw.Args,
		ret:           eventRaw.Ret,
		duration:      eventRaw.Duration,
		enterTime:     eventRaw.EnterTime,
		ptr:           eventRaw.Ptr,
		stackID:       eventRaw.StackId,
		probeRetEnter: eventRaw.ProbeRetEnter,
		probeRetExit:  eventRaw.ProbeRetExit,
	}
}

func newSyscallEventContextFromBPF(s *traceSession, eventRaw *bpfEvent, statePID int, pendingEnter *pendingSyscallState) syscallEventContext {
	view := newSyscallEventViewFromBPF(eventRaw)
	scMeta := syscallMeta(view.sysID)
	return newSyscallEventContextFromView(s, view, statePID, pendingEnter, payloadSectionsForEvent(eventRaw, scMeta))
}
