package main

import "sort"

func (st *TraceState) setUnfinishedEnabled(enabled bool) {
	if st == nil {
		return
	}
	st.unfinishedEnabled = enabled
	st.unqueuedUnfinished = nil
	st.inFlightUnfinished = nil
	if !enabled {
		return
	}
	st.ensureUnfinishedIndex()
	for tid, pending := range st.pendingSyscalls {
		if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 {
			continue
		}
		st.unqueuedUnfinished[tid] = struct{}{}
	}
}

func (st *TraceState) ensureUnfinishedIndex() {
	if st.unqueuedUnfinished == nil {
		st.unqueuedUnfinished = make(map[uint32]struct{})
	}
	if st.inFlightUnfinished == nil {
		st.inFlightUnfinished = make(map[uint32]struct{})
	}
}

func (st *TraceState) acquireUnfinishedViews(capacity int) []unfinishedSyscallView {
	if st == nil || capacity <= 0 {
		return nil
	}
	if cap(st.reusableUnfinished) < capacity {
		return make([]unfinishedSyscallView, 0, capacity)
	}
	views := st.reusableUnfinished[:0]
	st.reusableUnfinished = nil
	return views
}

func (st *TraceState) enqueueUnfinished(tid uint32) {
	if st == nil || !st.unfinishedEnabled || tid == 0 {
		return
	}
	st.ensureUnfinishedIndex()
	st.unqueuedUnfinished[tid] = struct{}{}
}

func (st *TraceState) deleteUnfinishedCandidate(tid uint32) {
	if st == nil || !st.unfinishedEnabled {
		return
	}
	delete(st.unqueuedUnfinished, tid)
	delete(st.inFlightUnfinished, tid)
}

func (st *TraceState) pendingForOtherTID(tid uint32) []unfinishedSyscallView {
	if st == nil || !st.unfinishedEnabled || tid == 0 || len(st.unqueuedUnfinished) == 0 {
		return nil
	}
	if len(st.unqueuedUnfinished) == 1 {
		if _, ok := st.unqueuedUnfinished[tid]; ok {
			return nil
		}
	}

	candidates := st.acquireUnfinishedViews(len(st.unqueuedUnfinished))
	for pendingTID := range st.unqueuedUnfinished {
		if pendingTID == tid {
			continue
		}
		pending := st.pendingSyscalls[pendingTID]
		if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 {
			st.deleteUnfinishedCandidate(pendingTID)
			continue
		}
		delete(st.unqueuedUnfinished, pendingTID)
		st.inFlightUnfinished[pendingTID] = struct{}{}
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

func (st *TraceState) requeueUnfinished(tid uint32) {
	if st == nil {
		return
	}
	delete(st.inFlightUnfinished, tid)
	pending := st.pendingSyscalls[tid]
	if pending == nil || pending.unfinishedPrinted || pending.probeRetEnter >= 2 {
		delete(st.unqueuedUnfinished, tid)
		return
	}
	st.ensureUnfinishedIndex()
	st.unqueuedUnfinished[tid] = struct{}{}
}
