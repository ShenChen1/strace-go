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
	envelope := newRawEventEnvelopeFromBPF(eventRaw)
	if !s.traceScope().AllowsPID(envelope.pid) {
		return
	}
	statePID := s.eventStatePID(envelope)
	stateUpdate := s.traceState().handleEnvelope(envelope)

	if stateUpdate.kind == traceStateLifecycle {
		s.lifecycleEventHandler().Handle(stateUpdate.lifecycleView, stateUpdate.lifecycleTask)
		return
	}

	if stateUpdate.kind == traceStateSyscallEnter {
		s.syscallJSONOutput().HandleEnter(newSyscallEnterEventContext(
			stateUpdate.syscallView,
			statePID,
			stateUpdate.payloadSections,
		))
		return
	}
	ev := newSyscallEventContext(s, eventRaw, statePID, stateUpdate.pendingEnter)

	s.syscallExitPipeline().Handle(ev)
}
