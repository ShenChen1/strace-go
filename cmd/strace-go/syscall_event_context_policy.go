package main

import "strace-go/pkg/event"

func (ev syscallEventContext) shouldOutput() bool {
	return ev.shouldPrint
}

func (ev syscallEventContext) shouldRunHandler() bool {
	return ev.shouldPrint || ev.isFDStateSyscall()
}

func (ev syscallEventContext) shouldUpdateFDState() bool {
	return shouldApplyFDStateEventWithTraits(
		ev.view,
		ev.payloadSections,
		ev.eventTraits(),
	)
}

func (ev syscallEventContext) shouldUpdateFDOffsets() bool {
	return shouldApplyFDOffsetEventWithTraits(ev.view, ev.eventTraits())
}

func (ev syscallEventContext) shouldCleanupClosedFD() bool {
	return shouldCleanupClosedFDEventWithTraits(ev.view, ev.eventTraits())
}

func (ev syscallEventContext) shouldEmitRawEnter(fdState event.FDPathReader) bool {
	if ev.filter == nil {
		return false
	}
	if ev.filter.DebugEvents() {
		return true
	}
	return checkShouldPrintFromView(printFilterRequest{
		view:          ev.eventView(),
		scMeta:        ev.effectiveSyscallMeta(),
		pathArguments: ev.pathArguments,
		targetPid:     ev.statePID,
		filter:        ev.filter,
		fdState:       fdState,
		eventFD:       ev.eventFDView,
	})
}

func (ev syscallEventContext) isFDStateSyscall() bool {
	return ev.eventTraits()&syscallEventTraitHandler != 0
}

func (ev syscallEventContext) shouldEmitStatus(optsStatus successfulFailedOptions) bool {
	return ev.eventView().shouldEmitStatus(ev.syscallName(), optsStatus)
}

func (view syscallEventView) shouldEmitStatus(syscallName string, optsStatus successfulFailedOptions) bool {
	if optsStatus.successfulOnly || optsStatus.failedOnly || len(optsStatus.traceStatus) > 0 {
		if view.probeRetEnter == 3 {
			return false
		}
	}
	if view.probeRetEnter == 3 {
		return true
	}

	isFailed := view.ret < 0 && view.ret >= -4095
	if syscallName == "exit" || syscallName == "exit_group" {
		isFailed = false
	}
	if optsStatus.successfulOnly && isFailed {
		return false
	}
	if optsStatus.failedOnly && !isFailed {
		return false
	}
	if len(optsStatus.traceStatus) > 0 {
		if optsStatus.traceStatus["successful"] && !isFailed {
			return true
		}
		if optsStatus.traceStatus["failed"] && isFailed {
			return true
		}
		return false
	}
	return true
}
