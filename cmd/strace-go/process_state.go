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
	if parentPID <= 0 || childPID <= 0 || parentPID == childPID {
		return
	}
	s.inheritFDMap(parentPID, childPID)
	s.inheritFDOffsets(parentPID, childPID)
	s.inheritFDDataFiles(parentPID, childPID)
}

func (s *traceSession) inheritFDMap(parentPID int, childPID int) {
	if s.fdMap == nil {
		return
	}
	parentPrefix := fdMapPrefix(parentPID)
	for key, target := range s.fdMap {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		childKey := fmt.Sprintf("%d:%s", childPID, strings.TrimPrefix(key, parentPrefix))
		s.fdMap[childKey] = target
	}
}

func (s *traceSession) inheritFDOffsets(parentPID int, childPID int) {
	if s.fdOffsets == nil {
		return
	}
	parentPrefix := fdMapPrefix(parentPID)
	for key, offset := range s.fdOffsets {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		childKey := fmt.Sprintf("%d:%s", childPID, strings.TrimPrefix(key, parentPrefix))
		s.fdOffsets[childKey] = offset
	}
}

func (s *traceSession) inheritFDDataFiles(parentPID int, childPID int) {
	if s.fdFiles == nil || s.fdMap == nil {
		return
	}
	parentPrefix := fdMapPrefix(parentPID)
	for key := range s.fdFiles {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		_, fd, ok := parseFDStateKey(key)
		if !ok {
			continue
		}
		childKey := fdStateKey(childPID, fd)
		target := s.fdMap[childKey]
		if !isFileBackedFDTarget(target) {
			continue
		}
		if f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", childPID, fd)); err == nil {
			s.fdFiles[childKey] = f
		}
	}
}

func (s *traceSession) cleanupProcessState(pid int) {
	s.cleanupFDMap(pid)
	s.cleanupFDOffsets(pid)
	s.cleanupFDDataFiles(pid)
}

func (s *traceSession) cleanupFDMap(pid int) {
	prefix := fdMapPrefix(pid)
	for key := range s.fdMap {
		if strings.HasPrefix(key, prefix) {
			delete(s.fdMap, key)
		}
	}
}

func (s *traceSession) cleanupFDOffsets(pid int) {
	prefix := fdMapPrefix(pid)
	for key := range s.fdOffsets {
		if strings.HasPrefix(key, prefix) {
			delete(s.fdOffsets, key)
		}
	}
}

func (s *traceSession) cleanupFDDataFiles(pid int) {
	prefix := fdMapPrefix(pid)
	for key, f := range s.fdFiles {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if f != nil {
			f.Close()
		}
		delete(s.fdFiles, key)
	}
}
