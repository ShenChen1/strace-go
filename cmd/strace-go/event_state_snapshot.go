package main

import "strace-go/pkg/handler"

// pendingSyscallSnapshot is the detached transfer view of a pending enter.
// Its payload slice is transferred from the state owner and released after
// the synchronous router finishes consuming the update.
type pendingSyscallSnapshot struct {
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

func (st *traceSyscallCorrelationState) acquirePendingSnapshot(pending *pendingSyscallState) *pendingSyscallSnapshot {
	snapshot := st.acquirePendingSnapshotSlot()
	*snapshot = pendingSyscallSnapshot{
		pid:               pending.pid,
		tid:               pending.tid,
		sysID:             pending.sysID,
		enterTime:         pending.enterTime,
		args:              pending.args,
		probeRetEnter:     pending.probeRetEnter,
		genericEnterRaw:   pending.genericEnterRaw,
		unfinishedPrinted: pending.unfinishedPrinted,
		payloadStorage:    pending.payloadStorage,
		payloadSections:   payloadSectionsFromStorage(pending.payloadStorage),
	}
	return snapshot
}

func (st *traceSyscallCorrelationState) acquirePendingSnapshotSlot() *pendingSyscallSnapshot {
	last := len(st.reusableSnapshots) - 1
	if last < 0 {
		return &pendingSyscallSnapshot{}
	}
	snapshot := st.reusableSnapshots[last]
	st.reusableSnapshots = st.reusableSnapshots[:last]
	return snapshot
}

func (st *traceSyscallCorrelationState) synthesizeGenericEnter(view *syscallEventView) *pendingSyscallSnapshot {
	if st == nil || view == nil {
		return nil
	}
	snapshot := st.acquirePendingSnapshotSlot()
	*snapshot = pendingSyscallSnapshot{
		pid:             view.pid,
		tid:             view.tid,
		sysID:           view.sysID,
		enterTime:       view.enterTime,
		args:            view.args,
		probeRetEnter:   -1,
		genericEnterRaw: true,
	}
	return snapshot
}

func (st *traceSyscallCorrelationState) releasePendingSnapshot(snapshot *pendingSyscallSnapshot) {
	if st == nil || snapshot == nil {
		return
	}
	storage := snapshot.payloadStorage
	snapshot.payloadStorage = nil
	snapshot.payloadSections = nil
	st.releasePayloadStorage(storage)
	*snapshot = pendingSyscallSnapshot{}
	st.reusableSnapshots = append(st.reusableSnapshots, snapshot)
}

func (snapshot *pendingSyscallSnapshot) enterView() syscallEventView {
	if snapshot == nil {
		return syscallEventView{}
	}
	return syscallEventView{
		valid:         true,
		pid:           snapshot.pid,
		tid:           snapshot.tid,
		sysID:         snapshot.sysID,
		eventType:     bpfEventTypeEnter,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          snapshot.args,
		enterTime:     snapshot.enterTime,
		probeRetEnter: snapshot.probeRetEnter,
	}
}
