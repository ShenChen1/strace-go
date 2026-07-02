package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func (s *traceSession) eventStatePID(eventRaw *bpfEvent) int {
	if eventRaw != nil && eventRaw.Pid != 0 {
		return int(eventRaw.Pid)
	}
	return s.targetPid
}

func fdMapPrefix(pid int) string {
	return fmt.Sprintf("%d:", pid)
}

func parseFDStateKey(key string) (int, int32, bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 2 || parts[1] == "cwd" {
		return 0, 0, false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	fd64, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return pid, int32(fd64), true
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
	st.InheritDataFiles(parentPID, childPID)
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

func (s *traceSession) inheritFDDataFiles(parentPID int, childPID int) {
	s.fdStateStore().InheritDataFiles(parentPID, childPID)
}

func (st *FDStateStore) InheritDataFiles(parentPID int, childPID int) {
	st.ensureMaps()
	parentPrefix := fdMapPrefix(parentPID)
	for key := range st.files {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		_, fd, ok := parseFDStateKey(key)
		if !ok {
			continue
		}
		childKey := fdStateKey(childPID, fd)
		target := st.paths[childKey]
		if !isFileBackedFDTarget(target) {
			continue
		}
		if f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", childPID, fd)); err == nil {
			st.files[childKey] = f
		}
	}
}

func (s *traceSession) cleanupProcessState(pid int) {
	s.fdStateStore().CleanupProcess(pid)
}

func (st *FDStateStore) CleanupProcess(pid int) {
	st.CleanupPaths(pid)
	st.CleanupOffsets(pid)
	st.CleanupDataFiles(pid)
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

func (s *traceSession) cleanupFDDataFiles(pid int) {
	s.fdStateStore().CleanupDataFiles(pid)
}

func (st *FDStateStore) CleanupDataFiles(pid int) {
	st.ensureMaps()
	prefix := fdMapPrefix(pid)
	for key, f := range st.files {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if f != nil {
			f.Close()
		}
		delete(st.files, key)
	}
}
