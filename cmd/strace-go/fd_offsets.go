package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func fdStateKey(targetPid int, fd int32) string {
	return fmt.Sprintf("%d:%d", targetPid, fd)
}

func shouldApplyFDOffsetEvent(view syscallEventView, syscallName string) bool {
	return shouldApplyFDOffsetEventWithTraits(
		view,
		syscallEventTraitsForView(view, syscallName),
	)
}

func shouldApplyFDOffsetEventWithTraits(view syscallEventView, traits syscallEventTraits) bool {
	if !view.valid || view.probeRetEnter == 3 || view.ret < 0 {
		return false
	}
	if traits&syscallEventTraitCreator != 0 {
		return true
	}
	if traits&syscallEventTraitOffset != 0 {
		return true
	}
	if traits&syscallEventTraitOffsetIO != 0 {
		return view.ret != 0
	}
	return false
}

func updateFDStateOffsetsFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	targetPID int,
	offsets map[string]int64,
) {
	if !src.view.valid || src.view.ret != 0 || !isFDArrayFDStateSyscall(scMeta.Name) {
		return
	}
	for _, section := range src.payloadSections {
		observation, ok := fdStateObservationFromSection(section)
		if !ok || observation.Flags&handler.FDStateFlagOffset == 0 {
			continue
		}
		offsets[fdStateKey(targetPID, observation.FD)] = observation.Offset
	}
}

func (st *FDStateStore) bufferFileOffsetFromView(view syscallEventView, scMeta meta.Syscall, statePID int) (int64, bool) {
	if !view.valid {
		return 0, false
	}
	st.ensureMaps()
	switch scMeta.Name {
	case "write":
		if st.tainted {
			return 0, false
		}
		fd := int32(view.args[0])
		key := fdStateKey(statePID, fd)
		if off, ok := st.offsets[key]; ok {
			return off, true
		}
	case "pwrite64":
		return int64(view.args[3]), true
	}
	return 0, false
}

func (st *FDStateStore) ApplyFDOffsets(update fdOffsetUpdate) {
	if st.tainted {
		return
	}
	st.updateOffsetsFromView(update.view, update.meta, update.statePID)
}

func (st *FDStateStore) updateOffsetsFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || view.probeRetEnter == 3 {
		return
	}
	st.ensureMaps()
	ret := view.ret
	if ret < 0 {
		return
	}
	if isFDStateCreatorForView(scMeta.Name, view) {
		key := fdStateKey(statePID, int32(ret))
		observation, ok := st.fdStates[key]
		if !ok || observation.Flags&handler.FDStateFlagOffset == 0 {
			delete(st.offsets, key)
			return
		}
		st.offsets[key] = observation.Offset
		return
	}

	switch scMeta.Name {
	case "open", "openat", "openat2", "open_tree", "creat":
		fd := int32(ret)
		key := fdStateKey(statePID, fd)
		st.offsets[key] = 0
		if observation, ok := st.fdStates[key]; ok && observation.Flags&handler.FDStateFlagOffset != 0 {
			st.offsets[key] = observation.Offset
		}
	case "dup", "dup2", "dup3", "fcntl", "fcntl64":
		oldFD, newFD, ok := duplicatedFDsFromView(view, scMeta)
		if !ok {
			return
		}
		oldKey := fdStateKey(statePID, oldFD)
		newKey := fdStateKey(statePID, newFD)
		if oldFD != newFD {
			delete(st.offsets, newKey)
		}
		if isFcntlFDStateSyscall(scMeta.Name) {
			if _, ok := st.fdStates[newKey]; !ok {
				return
			}
		}
		if off, ok := st.offsets[oldKey]; ok {
			st.offsets[newKey] = off
		}
	case "read", "write":
		if ret == 0 {
			return
		}
		fd := int32(view.args[0])
		key := fdStateKey(statePID, fd)
		if off, ok := st.offsets[key]; ok {
			st.offsets[key] = off + ret
		}
	case "lseek":
		st.offsets[fdStateKey(statePID, int32(view.args[0]))] = ret
	}
}
