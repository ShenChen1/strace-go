package main

func (ev syscallEventContext) pairedGenericEnter() bool {
	return ev.pendingEnter != nil && ev.pendingEnter.genericEnterRaw
}

func (ev syscallEventContext) shouldSuppressOutput() bool {
	return ev.syscallName() == "arch_prctl" && ev.eventView().args[0] == 0x1002
}

func (ev syscallEventContext) recordSummary(recorder traceSummaryRecorder) {
	if recorder == nil || !ev.shouldOutput() {
		return
	}
	view := ev.eventView()
	recorder.Record(ev.syscallName(), view.cpuDuration, view.duration, view.ret)
}

func (ev syscallEventContext) updateFDOffsets(port fdOffsetUpdatePort) {
	if port == nil || !ev.shouldUpdateFDOffsets() {
		return
	}
	port.ApplyFDOffsets(ev.fdOffsetUpdate())
}

func (ev syscallEventContext) fdOffsetUpdate() fdOffsetUpdate {
	return fdOffsetUpdate{
		view:     ev.eventView(),
		meta:     ev.effectiveSyscallMeta(),
		statePID: ev.statePID,
	}
}

func (ev syscallEventContext) cleanupClosedFD(port fdCloseUpdatePort) {
	if port == nil || !ev.shouldCleanupClosedFD() {
		return
	}
	port.CleanupClosedFD(ev.fdCloseUpdate())
}

func (ev syscallEventContext) fdCloseUpdate() fdCloseUpdate {
	return fdCloseUpdate{
		view:     ev.eventView(),
		meta:     ev.effectiveSyscallMeta(),
		statePID: ev.statePID,
	}
}

func (ev syscallEventContext) updateFDState(port fdStateUpdatePort) {
	if port == nil {
		return
	}
	port.ApplyFDState(ev.fdStateUpdate())
}

func (ev syscallEventContext) fdStateUpdate() fdStateUpdate {
	view := ev.eventView()
	return fdStateUpdate{
		source: fdStateSource{
			view:            view,
			payloadSections: ev.outputPayloadSections(),
		},
		meta:        ev.effectiveSyscallMeta(),
		flagDecoder: ev.fdFlags,
		pathText:    ev.pathText,
		targetPID:   ev.statePID,
	}
}
