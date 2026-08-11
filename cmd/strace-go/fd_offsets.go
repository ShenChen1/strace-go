package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func fdStateKey(targetPid int, fd int32) string {
	return fmt.Sprintf("%d:%d", targetPid, fd)
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

func (st *FDStateStore) updateOffsetsFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || view.probeRetEnter == 3 {
		return
	}
	st.ensureMaps()
	ret := view.ret
	if ret < 0 {
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
	case "dup", "dup2", "dup3":
		oldKey := fdStateKey(statePID, int32(view.args[0]))
		newFD := int32(ret)
		newKey := fdStateKey(statePID, newFD)
		if int32(view.args[0]) != newFD {
			delete(st.offsets, newKey)
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
