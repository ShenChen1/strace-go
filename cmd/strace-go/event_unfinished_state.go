package main

import (
	"sort"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// traceUnfinishedState owns text-mode unfinished candidate indexing and view
// recycling. It borrows pending payload sections only for one router update.
type traceUnfinishedState struct {
	enabled  bool
	unqueued map[uint32]struct{}
	inFlight map[uint32]struct{}
	reusable []unfinishedSyscallView
}

// unfinishedSyscallView borrows payload data from an in-flight pending state.
// It is valid only during the synchronous router call that owns the update.
type unfinishedSyscallView struct {
	pid             uint32
	tid             uint32
	sysID           uint32
	enterTime       uint64
	args            [6]uint64
	probeRetEnter   int32
	payloadSections []handler.PayloadSection
}

func (pending *pendingSyscallState) unfinishedView() unfinishedSyscallView {
	if pending == nil {
		return unfinishedSyscallView{}
	}
	return unfinishedSyscallView{
		pid:             pending.pid,
		tid:             pending.tid,
		sysID:           pending.sysID,
		enterTime:       pending.enterTime,
		args:            pending.args,
		probeRetEnter:   pending.probeRetEnter,
		payloadSections: pending.payloadSections,
	}
}

func (view unfinishedSyscallView) enterView() syscallEventView {
	return syscallEventView{
		valid:         true,
		pid:           view.pid,
		tid:           view.tid,
		sysID:         view.sysID,
		eventType:     bpfEventTypeEnter,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          view.args,
		enterTime:     view.enterTime,
		probeRetEnter: view.probeRetEnter,
	}
}

var nonBlockingUnfinishedSyscalls = buildNonBlockingUnfinishedSyscalls()

func buildNonBlockingUnfinishedSyscalls() [syscallEventTraitTableSize]bool {
	var table [syscallEventTraitTableSize]bool
	for sysID, scMeta := range meta.SyscallTable {
		if sysID >= uint32(len(table)) {
			continue
		}
		table[sysID] = isStableNonBlockingSyscall(scMeta.Name)
	}
	return table
}

// shouldTrackUnfinishedSyscall keeps the unknown-syscall behavior conservative.
func shouldTrackUnfinishedSyscall(sysID uint32) bool {
	if sysID < uint32(len(nonBlockingUnfinishedSyscalls)) {
		return !nonBlockingUnfinishedSyscalls[sysID]
	}
	return !isStableNonBlockingSyscall(syscallMeta(sysID).Name)
}

func isStableNonBlockingSyscall(name string) bool {
	switch name {
	case "getpid", "gettid", "getppid",
		"getuid", "geteuid", "getgid", "getegid",
		"getresuid", "getresgid", "getpgrp", "getpgid", "getsid",
		"getcpu", "gettimeofday", "time",
		"clock_gettime", "clock_gettime64", "clock_getres", "clock_getres_time64",
		"arch_prctl", "get_robust_list", "set_tid_address", "set_robust_list", "rseq":
		return true
	default:
		return false
	}
}

func (st *traceUnfinishedState) setEnabled(
	enabled bool,
	correlation *traceSyscallCorrelationState,
) {
	if st == nil {
		return
	}
	st.enabled = enabled
	st.unqueued = nil
	st.inFlight = nil
	if !enabled {
		return
	}
	st.ensureIndex()
	if correlation == nil {
		return
	}
	for tid, pending := range correlation.pendingSyscalls {
		if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 ||
			!shouldTrackUnfinishedSyscall(pending.sysID) {
			continue
		}
		st.unqueued[tid] = struct{}{}
	}
}

func (st *traceUnfinishedState) ensureIndex() {
	if st.unqueued == nil {
		st.unqueued = make(map[uint32]struct{})
	}
	if st.inFlight == nil {
		st.inFlight = make(map[uint32]struct{})
	}
}

func (st *traceUnfinishedState) acquireViews(capacity int) []unfinishedSyscallView {
	if st == nil || capacity <= 0 {
		return nil
	}
	if cap(st.reusable) < capacity {
		return make([]unfinishedSyscallView, 0, capacity)
	}
	views := st.reusable[:0]
	st.reusable = nil
	return views
}

func (st *traceUnfinishedState) releaseViews(views []unfinishedSyscallView) {
	if st == nil || views == nil {
		return
	}
	clear(views)
	st.reusable = views[:0]
}

func (st *traceUnfinishedState) enqueue(tid uint32, sysID uint32) {
	if st == nil || !st.enabled || tid == 0 || !shouldTrackUnfinishedSyscall(sysID) {
		return
	}
	st.ensureIndex()
	st.unqueued[tid] = struct{}{}
}

func (st *traceUnfinishedState) deleteCandidate(tid uint32) {
	if st == nil || !st.enabled {
		return
	}
	delete(st.unqueued, tid)
	delete(st.inFlight, tid)
}

func (st *traceUnfinishedState) pendingForOtherTID(
	tid uint32,
	correlation *traceSyscallCorrelationState,
) []unfinishedSyscallView {
	if st == nil || !st.enabled || tid == 0 || len(st.unqueued) == 0 || correlation == nil {
		return nil
	}
	if len(st.unqueued) == 1 {
		if _, ok := st.unqueued[tid]; ok {
			return nil
		}
	}

	candidates := st.acquireViews(len(st.unqueued))
	for pendingTID := range st.unqueued {
		if pendingTID == tid {
			continue
		}
		pending := correlation.pendingSyscalls[pendingTID]
		if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 ||
			!shouldTrackUnfinishedSyscall(pending.sysID) {
			st.deleteCandidate(pendingTID)
			continue
		}
		delete(st.unqueued, pendingTID)
		st.inFlight[pendingTID] = struct{}{}
		candidates = append(candidates, pending.unfinishedView())
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].enterTime != candidates[j].enterTime {
			return candidates[i].enterTime < candidates[j].enterTime
		}
		return candidates[i].tid < candidates[j].tid
	})
	return candidates
}

func (st *traceUnfinishedState) requeue(
	tid uint32,
	correlation *traceSyscallCorrelationState,
) {
	if st == nil {
		return
	}
	delete(st.inFlight, tid)
	if correlation == nil {
		return
	}
	pending := correlation.pendingSyscalls[tid]
	if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 ||
		!shouldTrackUnfinishedSyscall(pending.sysID) {
		delete(st.unqueued, tid)
		return
	}
	st.ensureIndex()
	st.unqueued[tid] = struct{}{}
}
