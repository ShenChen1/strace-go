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
	payloadSections   []handler.PayloadSection
}

func (st *TraceState) acquirePendingSnapshot(pending *pendingSyscallState) *pendingSyscallSnapshot {
	last := len(st.reusableSnapshots) - 1
	var snapshot *pendingSyscallSnapshot
	if last < 0 {
		snapshot = &pendingSyscallSnapshot{}
	} else {
		snapshot = st.reusableSnapshots[last]
		st.reusableSnapshots = st.reusableSnapshots[:last]
	}
	*snapshot = pendingSyscallSnapshot{
		pid:               pending.pid,
		tid:               pending.tid,
		sysID:             pending.sysID,
		enterTime:         pending.enterTime,
		args:              pending.args,
		probeRetEnter:     pending.probeRetEnter,
		genericEnterRaw:   pending.genericEnterRaw,
		unfinishedPrinted: pending.unfinishedPrinted,
		payloadSections:   pending.payloadSections,
	}
	return snapshot
}

func (st *TraceState) releasePendingSnapshot(snapshot *pendingSyscallSnapshot) {
	if st == nil || snapshot == nil {
		return
	}
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
