package main

// IMPACT: resolvePtrProbeRet returns the specific probe status for eventRaw.Ptr based on its argument index.
func resolvePtrProbeRet(eventRaw *bpfEvent) int32 {
	if eventRaw.Ptr == 0 {
		return 0
	}
	for i, val := range eventRaw.Args {
		if val == eventRaw.Ptr {
			return getArgProbeStatus(eventRaw.ProbeRetEnter, i)
		}
	}
	return eventRaw.ProbeRetEnter
}

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
	if !s.traceScope().Allows(eventRaw) {
		return
	}
	statePID := s.eventStatePID(eventRaw)
	stateUpdate := s.traceState().Handle(eventRaw)

	if stateUpdate.kind == traceStateLifecycle {
		s.lifecycleEventHandler().Handle(eventRaw, stateUpdate.lifecycleTask)
		return
	}

	scMeta := syscallMeta(eventRaw.SysId)

	if stateUpdate.kind == traceStateSyscallEnter {
		s.syscallJSONOutput().HandleEnter(eventRaw, newSyscallEventViewFromBPF(eventRaw), scMeta, statePID)
		return
	}
	ev := newSyscallEventContext(s, eventRaw, statePID, stateUpdate.pendingEnter)

	s.syscallExitPipeline().Handle(ev)
}
