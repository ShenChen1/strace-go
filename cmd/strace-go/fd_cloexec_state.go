package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func (st *FDStateStore) FDCloexecMap() map[string]bool {
	st.ensureMaps()
	return st.fdCloexec
}

func (st *FDStateStore) updateFDCloexecFromSource(src fdStateSource, scMeta meta.Syscall, targetPID int) {
	if !src.view.valid || src.view.ret < 0 {
		return
	}

	if policy, ok := fdCreatorPolicyFor(scMeta.Name, src.view); ok {
		if !hasFDStateSnapshotForFD(src, int32(src.view.ret)) {
			st.replaceFDCloexec(targetPID, int32(src.view.ret), false, false)
			return
		}
		state := policy.state(src)
		st.replaceFDCloexec(targetPID, int32(src.view.ret), state.cloexec, state.cloexecKnown)
		return
	}

	switch scMeta.Name {
	case "open", "openat", "openat2", "open_tree", "creat":
		enabled, known := createdFDCloexecState(src, scMeta.Name)
		st.replaceFDCloexec(targetPID, int32(src.view.ret), enabled, known)
	case "dup", "dup2", "dup3":
		st.updateDuplicatedFDCloexec(src.view, scMeta.Name, targetPID)
	case "close_range":
		st.updateCloseRangeState(src.view, targetPID)
	case "fcntl", "fcntl64":
		st.updateFcntlFDCloexec(src.view, scMeta.Name, targetPID)
	case "pipe", "pipe2", "socketpair":
		st.updateArrayFDCloexec(src, scMeta.Name, targetPID)
	}
}

func (st *FDStateStore) updateDuplicatedFDCloexec(view syscallEventView, syscallName string, targetPID int) {
	oldFD, newFD, ok := duplicatedFDsFromView(view, meta.Syscall{Name: syscallName})
	if !ok || oldFD == newFD {
		return
	}
	enabled, known := duplicatedFDCloexecState(view, syscallName)
	st.replaceFDCloexec(targetPID, newFD, enabled, known)
}

func (st *FDStateStore) updateFcntlFDCloexec(view syscallEventView, syscallName string, targetPID int) {
	if uint32(view.args[1]) == uint32(unix.F_SETFD) && view.ret == 0 {
		fd := int32(view.args[0])
		enabled := view.args[2]&uint64(unix.FD_CLOEXEC) != 0
		st.replaceFDCloexec(targetPID, fd, enabled, true)
		return
	}
	st.updateDuplicatedFDCloexec(view, syscallName, targetPID)
}

func (st *FDStateStore) updateArrayFDCloexec(src fdStateSource, syscallName string, targetPID int) {
	first, second, ok := fdArrayCloexecValues(src, syscallName)
	if !ok {
		return
	}
	enabled := arrayFDCloexecEnabled(src.view, syscallName)
	st.replaceFDCloexec(targetPID, first, enabled, true)
	st.replaceFDCloexec(targetPID, second, enabled, true)
}

func createdFDCloexecState(src fdStateSource, syscallName string) (bool, bool) {
	var flags uint64
	switch syscallName {
	case "open":
		flags = src.view.args[1]
	case "openat":
		flags = src.view.args[2]
	case "open_tree":
		flags = src.view.args[2]
	case "creat":
		return false, true
	case "openat2":
		var ok bool
		flags, ok = openHowFlagsFromPayload(src.payloadSections)
		if !ok {
			return false, false
		}
	default:
		return false, false
	}
	return flags&uint64(unix.O_CLOEXEC) != 0, true
}

func openHowFlagsFromPayload(sections []handler.PayloadSection) (uint64, bool) {
	for _, section := range sections {
		if section.Kind != handler.PayloadKindStruct ||
			section.Direction != handler.PayloadDirectionIn ||
			section.ArgIndex != 2 || section.ProbeRet != 0 || len(section.Data) < 8 {
			continue
		}
		return binary.LittleEndian.Uint64(section.Data[:8]), true
	}
	return 0, false
}

func duplicatedFDCloexecState(view syscallEventView, syscallName string) (bool, bool) {
	switch syscallName {
	case "dup", "dup2":
		return false, true
	case "dup3":
		return view.args[2]&uint64(unix.O_CLOEXEC) != 0, true
	case "fcntl", "fcntl64":
		switch uint32(view.args[1]) {
		case 0:
			return false, true
		case uint32(unix.F_DUPFD_CLOEXEC):
			return true, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func fdArrayCloexecValues(src fdStateSource, syscallName string) (int32, int32, bool) {
	argIndex := 0
	if syscallName == "socketpair" {
		argIndex = 3
	}
	data, ok := fdArrayPayloadData(src.payloadSections, argIndex)
	if !ok {
		return 0, 0, false
	}
	return int32(binary.LittleEndian.Uint32(data[0:4])), int32(binary.LittleEndian.Uint32(data[4:8])), true
}

func arrayFDCloexecEnabled(view syscallEventView, syscallName string) bool {
	if syscallName == "socketpair" {
		return view.args[1]&uint64(unix.SOCK_CLOEXEC) != 0
	}
	return syscallName == "pipe2" && view.args[1]&uint64(unix.O_CLOEXEC) != 0
}

func (st *FDStateStore) replaceFDCloexec(targetPID int, fd int32, enabled, known bool) {
	if targetPID <= 0 || fd < 0 {
		return
	}
	key := fdStateKey(targetPID, fd)
	delete(st.fdCloexec, key)
	if known {
		st.fdCloexec[key] = enabled
	}
}

func (st *FDStateStore) cleanupClosedFDCloexecFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || scMeta.Name != "close" || view.ret != 0 {
		return
	}
	delete(st.fdCloexec, fdStateKey(statePID, int32(view.args[0])))
}

func (st *FDStateStore) InheritFDCloexec(parentPID int, childPID int) {
	st.ensureMaps()
	parentPrefix := fdMapPrefix(parentPID)
	for key, enabled := range st.fdCloexec {
		if !strings.HasPrefix(key, parentPrefix) {
			continue
		}
		childKey := fmt.Sprintf("%d:%s", childPID, strings.TrimPrefix(key, parentPrefix))
		st.fdCloexec[childKey] = enabled
	}
}

func (st *FDStateStore) CleanupFDCloexec(pid int) {
	st.ensureMaps()
	prefix := fdMapPrefix(pid)
	for key := range st.fdCloexec {
		if strings.HasPrefix(key, prefix) {
			delete(st.fdCloexec, key)
		}
	}
}

func (st *FDStateStore) CloseOnExecProcess(pid int) {
	if pid <= 0 {
		return
	}
	st.ensureMaps()
	prefix := fdMapPrefix(pid)
	for key := range st.paths {
		if strings.HasPrefix(key, prefix) && !st.retainAfterExec(key) {
			delete(st.paths, key)
		}
	}
	for key := range st.offsets {
		if strings.HasPrefix(key, prefix) && !st.retainAfterExec(key) {
			delete(st.offsets, key)
		}
	}
	for key := range st.fdStates {
		if strings.HasPrefix(key, prefix) && !st.retainAfterExec(key) {
			delete(st.fdStates, key)
		}
	}
	for key, enabled := range st.fdCloexec {
		if strings.HasPrefix(key, prefix) && enabled {
			delete(st.fdCloexec, key)
		}
	}
}

func (st *FDStateStore) retainAfterExec(key string) bool {
	enabled, known := st.fdCloexec[key]
	return known && !enabled
}
