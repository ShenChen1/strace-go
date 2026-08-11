package main

import (
	"fmt"
	"strconv"
	"strings"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func fdStateKey(targetPid int, fd int32) string {
	return fmt.Sprintf("%d:%d", targetPid, fd)
}

func initFDTracking(targetPid int, fdMap map[string]string, metadata handler.FDMetadataServices) map[string]int64 {
	offsets := make(map[string]int64)
	if metadata == nil {
		return offsets
	}
	prefix := fmt.Sprintf("%d:", targetPid)
	for key := range fdMap {
		if !strings.HasPrefix(key, prefix) || strings.HasSuffix(key, ":cwd") {
			continue
		}
		fd64, err := strconv.ParseInt(strings.TrimPrefix(key, prefix), 10, 32)
		if err != nil {
			continue
		}
		fd := int32(fd64)
		if off, ok := metadata.FDOffset(targetPid, fd); ok {
			offsets[key] = off
		}
	}
	return offsets
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
		if metadata := st.Metadata(); metadata != nil {
			if off, ok := metadata.FDOffset(int(view.tid), fd); ok {
				if view.ret > 0 {
					off -= view.ret
				}
				return off, true
			}
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
	case "open", "openat", "openat2", "creat":
		fd := int32(ret)
		key := fdStateKey(statePID, fd)
		st.offsets[key] = 0
	case "dup", "dup2", "dup3":
		oldKey := fdStateKey(statePID, int32(view.args[0]))
		newFD := int32(ret)
		newKey := fdStateKey(statePID, newFD)
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
		} else if metadata := st.Metadata(); metadata != nil {
			if off, ok := metadata.FDOffset(int(view.tid), fd); ok {
				st.offsets[key] = off
			}
		}
	case "lseek":
		st.offsets[fdStateKey(statePID, int32(view.args[0]))] = ret
	}
}
