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
	return s.fdStateStore().BufferFileOffset(eventRaw, scMeta, s.eventStatePID(eventRaw))
}

func (st *FDStateStore) BufferFileOffset(eventRaw *bpfEvent, scMeta meta.Syscall, statePID int) (int64, bool) {
	st.ensureMaps()
	switch scMeta.Name {
	case "write":
		fd := int32(eventRaw.Args[0])
		key := fdStateKey(statePID, fd)
		if off, ok := st.offsets[key]; ok {
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
	s.fdStateStore().UpdateOffsets(eventRaw, scMeta, s.eventStatePID(eventRaw))
}

func (st *FDStateStore) UpdateOffsets(eventRaw *bpfEvent, scMeta meta.Syscall, statePID int) {
	if eventRaw.ProbeRetEnter == 3 {
		return
	}
	st.ensureMaps()
	ret := eventRaw.Ret
	if ret < 0 {
		return
	}

	switch scMeta.Name {
	case "open", "openat", "openat2", "creat":
		fd := int32(ret)
		key := fdStateKey(statePID, fd)
		st.offsets[key] = 0
		st.RememberDataFile(eventRaw, statePID, fd)
	case "dup", "dup2", "dup3":
		oldKey := fdStateKey(statePID, int32(eventRaw.Args[0]))
		newFD := int32(ret)
		newKey := fdStateKey(statePID, newFD)
		if off, ok := st.offsets[oldKey]; ok {
			st.offsets[newKey] = off
		}
		st.RememberDataFile(eventRaw, statePID, newFD)
	case "read", "write":
		if ret == 0 {
			return
		}
		fd := int32(eventRaw.Args[0])
		key := fdStateKey(statePID, fd)
		if off, ok := st.offsets[key]; ok {
			st.offsets[key] = off + ret
		} else if off, ok := readProcFDOffset(int(eventRaw.Tid), fd); ok {
			st.offsets[key] = off
		}
	case "lseek":
		st.offsets[fdStateKey(statePID, int32(eventRaw.Args[0]))] = ret
	}
}

func (s *traceSession) rememberFDDataFile(eventRaw *bpfEvent, fd int32) {
	s.fdStateStore().RememberDataFile(eventRaw, s.eventStatePID(eventRaw), fd)
}

func (st *FDStateStore) RememberDataFile(eventRaw *bpfEvent, statePID int, fd int32) {
	st.ensureMaps()
	key := fdStateKey(statePID, fd)
	target := st.paths[key]
	if !isFileBackedFDTarget(target) {
		return
	}
	if old := st.files[key]; old != nil {
		old.Close()
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd))
	if err == nil {
		st.files[key] = f
	}
}

func (s *traceSession) closeFDDataFiles() {
	s.fdStateStore().CloseFiles()
}

func (st *FDStateStore) CloseFiles() {
	st.ensureMaps()
	for key, f := range st.files {
		if f != nil {
			f.Close()
		}
		delete(st.files, key)
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
