package main

func newSyscallEventContextFromBPF(s *traceSession, eventRaw *bpfEvent, statePID int, pendingEnter *pendingSyscallState) syscallEventContext {
	view := newSyscallEventViewFromBPF(eventRaw)
	scMeta := syscallMeta(view.sysID)
	return newSyscallEventContextFromView(s, view, statePID, pendingEnter, payloadSectionsForEvent(eventRaw, scMeta))
}
