package main

import "strace-go/pkg/handler"

// traceSyscallCorrelationState owns syscall edge data that must survive until
// the matching exit or lifecycle cleanup. It is used only by the event loop.
type traceSyscallCorrelationState struct {
	pendingSyscalls   map[uint32]*pendingSyscallState
	reusablePending   []*pendingSyscallState
	reusableSnapshots []*pendingSyscallSnapshot
	reusablePayload   []*tracePayloadStorage
	reusableExits     []*pendingExitState
	pendingExits      map[uint32]*pendingExitState
	pendingExecArgs   map[int]string
	suspendedSyscalls map[int]string
}

type pendingSyscallState struct {
	pid               uint32
	tid               uint32
	sysID             uint32
	enterTime         uint64
	args              [6]uint64
	probeRetEnter     int32
	genericEnterRaw   bool
	unfinishedPrinted bool
	payloadStorage    *tracePayloadStorage
	payloadSections   []handler.PayloadSection
}

type pendingExitState struct {
	view            syscallEventView
	payloadStorage  *tracePayloadStorage
	payloadSections []handler.PayloadSection
}

func (c *traceSyscallCorrelationState) pendingCount() int {
	if c == nil {
		return 0
	}
	return len(c.pendingSyscalls)
}

func (pending *pendingSyscallState) enterView() syscallEventView {
	return syscallEventView{
		valid:         true,
		pid:           pending.pid,
		tid:           pending.tid,
		sysID:         pending.sysID,
		eventType:     bpfEventTypeEnter,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          pending.args,
		enterTime:     pending.enterTime,
		probeRetEnter: pending.probeRetEnter,
	}
}

func (c *traceSyscallCorrelationState) rememberEnterEvent(
	view *syscallEventView,
	payload []handler.PayloadSection,
) bool {
	if c.pendingSyscalls == nil {
		c.pendingSyscalls = make(map[uint32]*pendingSyscallState)
	}
	if pending := c.pendingSyscalls[view.tid]; pending != nil && pending.sysID == view.sysID {
		pending.genericEnterRaw = pending.genericEnterRaw || isGenericEnterView(view)
		pending.unfinishedPrinted = pending.unfinishedPrinted || view.probeRetEnter >= 2
		pending.payloadStorage = c.mergePayloadSectionsIntoStorage(pending.payloadStorage, payload)
		pending.payloadSections = payloadSectionsFromStorage(pending.payloadStorage)
		return false
	}
	if pending := c.pendingSyscalls[view.tid]; pending != nil {
		delete(c.pendingSyscalls, view.tid)
		c.releasePendingSyscall(pending)
	}
	pending := c.acquirePendingSyscall()
	storage := c.copyPayloadSectionsIntoStorage(payload)
	*pending = pendingSyscallState{
		pid:               view.pid,
		tid:               view.tid,
		sysID:             view.sysID,
		enterTime:         view.enterTime,
		args:              view.args,
		probeRetEnter:     view.probeRetEnter,
		genericEnterRaw:   isGenericEnterView(view),
		unfinishedPrinted: view.probeRetEnter >= 2,
		payloadStorage:    storage,
		payloadSections:   payloadSectionsFromStorage(storage),
	}
	c.pendingSyscalls[view.tid] = pending
	return true
}

func (c *traceSyscallCorrelationState) acquirePendingSyscall() *pendingSyscallState {
	last := len(c.reusablePending) - 1
	if last < 0 {
		return &pendingSyscallState{}
	}
	pending := c.reusablePending[last]
	c.reusablePending = c.reusablePending[:last]
	return pending
}

func (c *traceSyscallCorrelationState) releasePendingSyscall(pending *pendingSyscallState) {
	if c == nil || pending == nil {
		return
	}
	storage := pending.payloadStorage
	pending.payloadStorage = nil
	pending.payloadSections = nil
	c.releasePayloadStorage(storage)
	*pending = pendingSyscallState{}
	c.reusablePending = append(c.reusablePending, pending)
}

func (c *traceSyscallCorrelationState) rememberPayloadFragment(
	view syscallEventView,
	payload []handler.PayloadSection,
) {
	if c.pendingSyscalls == nil {
		return
	}
	pending := c.pendingSyscalls[view.tid]
	if pending == nil || pending.sysID != view.sysID {
		return
	}
	pending.payloadStorage = c.mergePayloadSectionsIntoStorage(pending.payloadStorage, payload)
	pending.payloadSections = payloadSectionsFromStorage(pending.payloadStorage)
}

func (c *traceSyscallCorrelationState) rememberPendingExit(
	view *syscallEventView,
	payload []handler.PayloadSection,
) {
	if c.pendingExits == nil {
		c.pendingExits = make(map[uint32]*pendingExitState)
	}
	if previous := c.pendingExits[view.tid]; previous != nil {
		c.releasePendingExit(*previous)
		c.releasePendingExitOwner(previous)
	}
	pending := c.acquirePendingExit()
	storage := c.copyPayloadSectionsIntoStorage(payload)
	*pending = pendingExitState{
		view:            *view,
		payloadStorage:  storage,
		payloadSections: payloadSectionsFromStorage(storage),
	}
	c.pendingExits[view.tid] = pending
}

func (c *traceSyscallCorrelationState) takePendingExit(view *syscallEventView) (pendingExitState, bool) {
	pending, ok := c.takePendingExitForTID(view.tid)
	if !ok {
		return pendingExitState{}, false
	}
	if pending.view.sysID != view.sysID || pending.view.enterTime != view.enterTime {
		c.releasePendingExit(pending)
		return pendingExitState{}, false
	}
	return pending, true
}

func (c *traceSyscallCorrelationState) takePendingExitForTID(tid uint32) (pendingExitState, bool) {
	if c.pendingExits == nil {
		return pendingExitState{}, false
	}
	pending, ok := c.pendingExits[tid]
	delete(c.pendingExits, tid)
	if !ok || pending == nil {
		return pendingExitState{}, false
	}
	value := *pending
	c.releasePendingExitOwner(pending)
	return value, true
}

func (c *traceSyscallCorrelationState) releasePendingExit(pending pendingExitState) {
	if c == nil {
		return
	}
	c.releasePayloadStorage(pending.payloadStorage)
}

func (c *traceSyscallCorrelationState) acquirePendingExit() *pendingExitState {
	last := len(c.reusableExits) - 1
	if last < 0 {
		return &pendingExitState{}
	}
	pending := c.reusableExits[last]
	c.reusableExits = c.reusableExits[:last]
	return pending
}

func (c *traceSyscallCorrelationState) releasePendingExitOwner(pending *pendingExitState) {
	if c == nil || pending == nil {
		return
	}
	*pending = pendingExitState{}
	c.reusableExits = append(c.reusableExits, pending)
}

func (c *traceSyscallCorrelationState) consumeEnterEvent(
	view *syscallEventView,
) *pendingSyscallSnapshot {
	if !isExitView(view) || c.pendingSyscalls == nil {
		return nil
	}
	pending := c.pendingSyscalls[view.tid]
	delete(c.pendingSyscalls, view.tid)
	if pending == nil {
		return nil
	}
	if pending.sysID != view.sysID {
		c.releasePendingSyscall(pending)
		return nil
	}
	snapshot := c.acquirePendingSnapshot(pending)
	pending.payloadStorage = nil
	pending.payloadSections = nil
	c.releasePendingSyscall(pending)
	return snapshot
}

func (c *traceSyscallCorrelationState) rememberPendingExecArgs(tid int, argLine string) {
	if c.pendingExecArgs == nil {
		c.pendingExecArgs = make(map[int]string)
	}
	c.pendingExecArgs[tid] = argLine
}

func (c *traceSyscallCorrelationState) takePendingExecArgs(tid int) (string, bool) {
	argLine, ok := c.pendingExecArgs[tid]
	delete(c.pendingExecArgs, tid)
	return argLine, ok
}

func (c *traceSyscallCorrelationState) pendingExecArgsFor(tid int) (string, bool) {
	argLine, ok := c.pendingExecArgs[tid]
	return argLine, ok
}

func (c *traceSyscallCorrelationState) deletePendingExecArgs(tid int) {
	delete(c.pendingExecArgs, tid)
}

func (c *traceSyscallCorrelationState) rememberSuspendedSyscall(tid int, name string) {
	if c.suspendedSyscalls == nil {
		c.suspendedSyscalls = make(map[int]string)
	}
	c.suspendedSyscalls[tid] = name
}

func (c *traceSyscallCorrelationState) deleteSuspendedSyscall(tid int) {
	delete(c.suspendedSyscalls, tid)
}

func (c *traceSyscallCorrelationState) consumeSuspendedSyscall(tid int) bool {
	if c.suspendedSyscalls == nil {
		return false
	}
	_, ok := c.suspendedSyscalls[tid]
	if ok {
		delete(c.suspendedSyscalls, tid)
	}
	return ok
}

func (c *traceSyscallCorrelationState) markUnfinishedPrinted(tid uint32) {
	if c == nil {
		return
	}
	if pending := c.pendingSyscalls[tid]; pending != nil {
		pending.unfinishedPrinted = true
	}
}

func (c *traceSyscallCorrelationState) clearTask(tid uint32) {
	if c == nil {
		return
	}
	delete(c.pendingExecArgs, int(tid))
	delete(c.suspendedSyscalls, int(tid))
	if pending := c.pendingSyscalls[tid]; pending != nil {
		delete(c.pendingSyscalls, tid)
		c.releasePendingSyscall(pending)
	}
	if pendingExit, ok := c.pendingExits[tid]; ok {
		if pendingExit != nil {
			c.releasePendingExit(*pendingExit)
			c.releasePendingExitOwner(pendingExit)
		}
		delete(c.pendingExits, tid)
	}
}
