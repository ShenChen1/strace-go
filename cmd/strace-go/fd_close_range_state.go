package main

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const closeRangeKnownFlags = unix.CLOSE_RANGE_UNSHARE | unix.CLOSE_RANGE_CLOEXEC

func (st *FDStateStore) updateCloseRangeState(view syscallEventView, targetPID int) {
	if !view.valid || view.eventType != bpfEventTypeExit || view.ret != 0 ||
		view.probeRetEnter == 3 || targetPID <= 0 {
		return
	}

	first := uint32(view.args[0])
	last := uint32(view.args[1])
	flags := uint32(view.args[2])
	if first > last || flags&^uint32(closeRangeKnownFlags) != 0 {
		return
	}
	if flags&uint32(unix.CLOSE_RANGE_CLOEXEC) != 0 {
		st.markCloseRangeCloexec(targetPID, first, last)
		return
	}
	st.removeCloseRangeState(targetPID, first, last)
}

func (st *FDStateStore) markCloseRangeCloexec(targetPID int, first, last uint32) {
	prefix := fdMapPrefix(targetPID)
	for key := range st.paths {
		st.markCloseRangeKey(prefix, key, first, last)
	}
	for key := range st.offsets {
		st.markCloseRangeKey(prefix, key, first, last)
	}
	for key := range st.fdStates {
		st.markCloseRangeKey(prefix, key, first, last)
	}
	for key := range st.fdCloexec {
		st.markCloseRangeKey(prefix, key, first, last)
	}
}

func (st *FDStateStore) markCloseRangeKey(prefix, key string, first, last uint32) {
	if closeRangeKeyInRange(key, prefix, first, last) {
		st.fdCloexec[key] = true
	}
}

func (st *FDStateStore) removeCloseRangeState(targetPID int, first, last uint32) {
	prefix := fdMapPrefix(targetPID)
	for key := range st.paths {
		if closeRangeKeyInRange(key, prefix, first, last) {
			delete(st.paths, key)
		}
	}
	for key := range st.offsets {
		if closeRangeKeyInRange(key, prefix, first, last) {
			delete(st.offsets, key)
		}
	}
	for key := range st.fdStates {
		if closeRangeKeyInRange(key, prefix, first, last) {
			delete(st.fdStates, key)
		}
	}
	for key := range st.fdCloexec {
		if closeRangeKeyInRange(key, prefix, first, last) {
			delete(st.fdCloexec, key)
		}
	}
}

func closeRangeKeyInRange(key, prefix string, first, last uint32) bool {
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	fd, err := strconv.ParseUint(strings.TrimPrefix(key, prefix), 10, 32)
	return err == nil && fd >= uint64(first) && fd <= uint64(last)
}
