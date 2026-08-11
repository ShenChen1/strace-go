package main

import "sort"

func (st *TraceState) ensureUnfinishedIndex() {
	if st.unqueuedUnfinished == nil {
		st.unqueuedUnfinished = make(map[uint32]struct{})
	}
	if st.inFlightUnfinished == nil {
		st.inFlightUnfinished = make(map[uint32]struct{})
	}
}

func (st *TraceState) enqueueUnfinished(tid uint32) {
	if st == nil || tid == 0 {
		return
	}
	st.ensureUnfinishedIndex()
	st.unqueuedUnfinished[tid] = struct{}{}
}

func (st *TraceState) deleteUnfinishedCandidate(tid uint32) {
	if st == nil {
		return
	}
	delete(st.unqueuedUnfinished, tid)
	delete(st.inFlightUnfinished, tid)
}

func (st *TraceState) pendingForOtherTID(tid uint32) []pendingSyscallState {
	if st == nil || tid == 0 || len(st.unqueuedUnfinished) == 0 {
		return nil
	}
	if len(st.unqueuedUnfinished) == 1 {
		if _, ok := st.unqueuedUnfinished[tid]; ok {
			return nil
		}
	}

	candidates := make([]pendingSyscallState, 0, len(st.unqueuedUnfinished))
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
		candidates = append(candidates, copyPendingSyscallState(*pending))
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
