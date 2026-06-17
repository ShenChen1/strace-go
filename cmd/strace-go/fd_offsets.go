package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"strace-go/pkg/meta"
)

func fdStateKey(targetPid int, fd int32) string {
	return fmt.Sprintf("%d:%d", targetPid, fd)
}

func initFDTracking(targetPid int, fdMap map[string]string) (map[string]int64, map[string]*os.File) {
	offsets := make(map[string]int64)
	files := make(map[string]*os.File)
	prefix := fmt.Sprintf("%d:", targetPid)
	for key, target := range fdMap {
		if !strings.HasPrefix(key, prefix) || strings.HasSuffix(key, ":cwd") {
			continue
		}
		fd64, err := strconv.ParseInt(strings.TrimPrefix(key, prefix), 10, 32)
		if err != nil {
			continue
		}
		fd := int32(fd64)
		if off, ok := readProcFDOffset(targetPid, fd); ok {
			offsets[key] = off
		}
		if isFileBackedFDTarget(target) {
			if f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", targetPid, fd)); err == nil {
				files[key] = f
			}
		}
	}
	return offsets, files
}

func readProcFDOffset(pid int, fd int32) (int64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pos:") {
			continue
		}
		pos := strings.TrimSpace(strings.TrimPrefix(line, "pos:"))
		off, err := strconv.ParseInt(pos, 10, 64)
		if err == nil {
			return off, true
		}
	}
	return 0, false
}

func (s *traceSession) bufferFileOffset(eventRaw *bpfEvent, scMeta meta.Syscall) (int64, bool) {
	switch scMeta.Name {
	case "write":
		fd := int32(eventRaw.Args[0])
		key := fdStateKey(s.targetPid, fd)
		if off, ok := s.fdOffsets[key]; ok {
			return off, true
		}
		if off, ok := readProcFDOffset(int(eventRaw.Tid), fd); ok {
			if eventRaw.Ret > 0 {
				off -= eventRaw.Ret
			}
			return off, true
		}
	case "pwrite64":
		return int64(eventRaw.Args[3]), true
	}
	return 0, false
}

func (s *traceSession) updateFDOffsets(eventRaw *bpfEvent, scMeta meta.Syscall) {
	if eventRaw.ProbeRetEnter == 3 {
		return
	}
	if s.fdOffsets == nil {
		s.fdOffsets = make(map[string]int64)
	}
	if s.fdFiles == nil {
		s.fdFiles = make(map[string]*os.File)
	}
	ret := eventRaw.Ret
	if ret < 0 {
		return
	}

	switch scMeta.Name {
	case "open", "openat", "openat2", "creat":
		fd := int32(ret)
		key := fdStateKey(s.targetPid, fd)
		s.fdOffsets[key] = 0
		s.rememberFDDataFile(eventRaw, fd)
	case "dup", "dup2", "dup3":
		oldKey := fdStateKey(s.targetPid, int32(eventRaw.Args[0]))
		newFD := int32(ret)
		newKey := fdStateKey(s.targetPid, newFD)
		if off, ok := s.fdOffsets[oldKey]; ok {
			s.fdOffsets[newKey] = off
		}
		s.rememberFDDataFile(eventRaw, newFD)
	case "read", "write":
		if ret == 0 {
			return
		}
		fd := int32(eventRaw.Args[0])
		key := fdStateKey(s.targetPid, fd)
		if off, ok := s.fdOffsets[key]; ok {
			s.fdOffsets[key] = off + ret
		} else if off, ok := readProcFDOffset(int(eventRaw.Tid), fd); ok {
			s.fdOffsets[key] = off
		}
	case "lseek":
		s.fdOffsets[fdStateKey(s.targetPid, int32(eventRaw.Args[0]))] = ret
	}
}

func (s *traceSession) rememberFDDataFile(eventRaw *bpfEvent, fd int32) {
	key := fdStateKey(s.targetPid, fd)
	target := s.fdMap[key]
	if !isFileBackedFDTarget(target) {
		return
	}
	if old := s.fdFiles[key]; old != nil {
		old.Close()
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd))
	if err == nil {
		s.fdFiles[key] = f
	}
}

func (s *traceSession) closeFDDataFiles() {
	for key, f := range s.fdFiles {
		if f != nil {
			f.Close()
		}
		delete(s.fdFiles, key)
	}
}

func isFileBackedFDTarget(target string) bool {
	if target == "" {
		return false
	}
	switch {
	case strings.HasPrefix(target, "socket:"),
		strings.HasPrefix(target, "socket:["),
		strings.HasPrefix(target, "pipe:"),
		strings.HasPrefix(target, "pipe:["),
		strings.HasPrefix(target, "anon_inode:"),
		strings.HasPrefix(target, "{"),
		strings.HasPrefix(target, "NETLINK:"):
		return false
	}
	return true
}
