package main

// IMPACT: getArgProbeStatus decodes the bitmask for entry argument success flag.
func getArgProbeStatus(probeRetEnter int32, argIndex int) int32 {
	if probeRetEnter >= 0 {
		return 0
	}
	if probeRetEnter == -1 {
		return -1
	}
	mask := -probeRetEnter - 1
	if (mask & (1 << argIndex)) != 0 {
		return -2
	}
	return 0
}

// IMPACT: handleEvent parses, decodes, and routes tracing events to print handlers or fd updates.
func (s *traceSession) handleEvent(eventRaw *bpfEvent) {
	stateView := newTraceStateEventViewFromBPF(eventRaw)
	if !s.traceScope().AllowsPID(stateView.pid) {
		return
	}
	statePID := s.eventStatePID(stateView)
	stateUpdate := s.traceState().handleView(stateView)

	if stateUpdate.kind == traceStateLifecycle {
		s.lifecycleEventHandler().Handle(stateUpdate.view, stateUpdate.lifecycleTask)
		return
	}

	if stateUpdate.kind == traceStateSyscallEnter {
		s.syscallJSONOutput().HandleEnter(newSyscallEnterEventContext(eventRaw, statePID))
		return
	}
	ev := newSyscallEventContext(s, eventRaw, statePID, stateUpdate.pendingEnter)

	s.syscallExitPipeline().Handle(ev)
}
