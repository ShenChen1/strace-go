package main

import (
	"fmt"
	"strings"
)

func (s *traceSession) eventStatePID(envelope traceEventEnvelope) int {
	if envelope.valid && envelope.pid != 0 {
		return int(envelope.pid)
	}
	return s.targetPid
}

func fdMapPrefix(pid int) string {
	return fmt.Sprintf("%d:", pid)
}

func (st *FDStateStore) InheritProcessState(parentPID int, childPID int) {
	if parentPID <= 0 || childPID <= 0 || parentPID == childPID {
		return
	}
	st.InheritPaths(parentPID, childPID)
	st.InheritOffsets(parentPID, childPID)
}

func (st *FDStateStore) InheritPaths(parentPID int, childPID int) {
	st.ensureMaps()
	parentPrefix := fdMapPrefix(parentPID)
	for key, target := range st.paths {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		childKey := fmt.Sprintf("%d:%s", childPID, strings.TrimPrefix(key, parentPrefix))
		st.paths[childKey] = target
	}
}

func (st *FDStateStore) InheritOffsets(parentPID int, childPID int) {
	st.ensureMaps()
	parentPrefix := fdMapPrefix(parentPID)
	for key, offset := range st.offsets {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		childKey := fmt.Sprintf("%d:%s", childPID, strings.TrimPrefix(key, parentPrefix))
		st.offsets[childKey] = offset
	}
}

func (st *FDStateStore) CleanupProcess(pid int) {
	st.CleanupPaths(pid)
	st.CleanupOffsets(pid)
}

func (st *FDStateStore) CleanupPaths(pid int) {
	st.ensureMaps()
	prefix := fdMapPrefix(pid)
	for key := range st.paths {
		if strings.HasPrefix(key, prefix) {
			delete(st.paths, key)
		}
	}
}

func (st *FDStateStore) CleanupOffsets(pid int) {
	st.ensureMaps()
	prefix := fdMapPrefix(pid)
	for key := range st.offsets {
		if strings.HasPrefix(key, prefix) {
			delete(st.offsets, key)
		}
	}
}
