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
	if ev.detached {
		if optsStatus.successfulOnly || optsStatus.failedOnly {
			return false
		}
		if optsStatus.hasStatusSet() {
			return optsStatus.traceStatus["detached"]
		}
		return true
	}
	return ev.eventView().shouldEmitStatus(ev.syscallName(), optsStatus)
}

func (ev syscallEventContext) withNonLeaderExecDetachedStatus(policy traceEventOutputPolicy) syscallEventContext {
	view := ev.eventView()
	if view.ret == 0 && view.pid != 0 && view.pid != view.tid && isExecSyscall(ev.syscallName()) {
		ev.detached = true
		ev.detachedByStatus = detachedStatusSelected(policy)
	}
	return ev
}

func detachedStatusSelected(policy traceEventOutputPolicy) bool {
	statusPolicy, ok := policy.(traceDetachedStatusPolicy)
	return ok && statusPolicy.DetachedStatusSelected()
}

func (view syscallEventView) shouldEmitStatus(syscallName string, optsStatus successfulFailedOptions) bool {
	if view.probeRetEnter == 3 {
		if optsStatus.successfulOnly || optsStatus.failedOnly {
			return false
		}
		if optsStatus.hasStatusSet() {
			return optsStatus.traceStatus["unavailable"]
		}
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
	if optsStatus.hasStatusSet() {
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
