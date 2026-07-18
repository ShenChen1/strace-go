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

func (s *traceSession) inheritProcessState(parentPID int, childPID int) {
	s.fdStateStore().InheritProcessState(parentPID, childPID)
}

func (st *FDStateStore) InheritProcessState(parentPID int, childPID int) {
	if parentPID <= 0 || childPID <= 0 || parentPID == childPID {
		return
	}
	st.InheritPaths(parentPID, childPID)
	st.InheritOffsets(parentPID, childPID)
}

func (s *traceSession) inheritFDMap(parentPID int, childPID int) {
	s.fdStateStore().InheritPaths(parentPID, childPID)
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

func (s *traceSession) inheritFDOffsets(parentPID int, childPID int) {
	s.fdStateStore().InheritOffsets(parentPID, childPID)
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

func (s *traceSession) cleanupProcessState(pid int) {
	s.fdStateStore().CleanupProcess(pid)
}

func (st *FDStateStore) CleanupProcess(pid int) {
	st.CleanupPaths(pid)
	st.CleanupOffsets(pid)
}

func (s *traceSession) cleanupFDMap(pid int) {
	s.fdStateStore().CleanupPaths(pid)
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

func (s *traceSession) cleanupFDOffsets(pid int) {
	s.fdStateStore().CleanupOffsets(pid)
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
