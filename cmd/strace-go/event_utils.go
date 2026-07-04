package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strings"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// IMPACT: updateFDMap dynamically tracks fd modifications inside open, dup, socket and close syscalls.
func updateFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, targetPid int, fdMap map[string]string) {
	updateFdReturnMap(eventRaw, scMeta, targetPid, fdMap)
	updateEventfdCount(eventRaw, scMeta, targetPid, fdMap)
	updateOpenedPathFDMap(eventRaw, scMeta, rawStrArg, targetPid, fdMap)
	updateDupFDMap(eventRaw, scMeta, targetPid, fdMap)
	updatePipeFDMapFromPayload(eventRaw, scMeta, targetPid, fdMap)
	updateSocketpairFDMap(eventRaw, scMeta, targetPid, fdMap)
	updateSocketFDMap(eventRaw, scMeta, targetPid, fdMap)
	updateNetlinkFDMap(eventRaw, scMeta, targetPid, fdMap)
	updateCwdFDMap(eventRaw, scMeta, rawStrArg, targetPid, fdMap)
}

func updateFdReturnMap(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if eventRaw.Ret < 0 || !isFdReturnSyscall(scMeta.Name) {
		return
	}
	linkPath := fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Pid, eventRaw.Ret)
	target, err := os.Readlink(linkPath)
	if err == nil {
		if strings.HasPrefix(target, "anon_inode:[eventfd]") {
			if info := formatEventfdTarget(linkPath, eventRaw, scMeta, false); info != "" {
				target = info
			}
		}
		fdMap[fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Ret))] = target
		return
	}
	if scMeta.Name == "eventfd" || scMeta.Name == "eventfd2" {
		if info := formatEventfdTarget(linkPath, eventRaw, scMeta, true); info != "" {
			fdMap[fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Ret))] = info
		}
	}
}

func formatEventfdTarget(linkPath string, eventRaw *bpfEvent, scMeta meta.Syscall, force bool) string {
	flags := uint64(0)
	if len(eventRaw.Args) > 1 {
		flags = eventRaw.Args[1]
	}
	forceCount := force || scMeta.Name == "eventfd" || scMeta.Name == "eventfd2"
	return handler.FormatEventfdInfo(linkPath, uint64(uint32(eventRaw.Args[0])), flags, forceCount)
}

func updateEventfdCount(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if scMeta.Name != "read" || eventRaw.Ret != 8 {
		return
	}
	fd := int32(eventRaw.Args[0])
	key := fmt.Sprintf("%d:%d", targetPid, fd)
	target, ok := fdMap[key]
	if !ok || !strings.Contains(target, "eventfd-count=") {
		return
	}
	isSem := strings.Contains(target, "eventfd-semaphore=1")
	re := regexp.MustCompile(`eventfd-count=([^,]+)`)
	m := re.FindStringSubmatch(target)
	if len(m) != 2 {
		return
	}
	var oldVal uint64
	if strings.HasPrefix(m[1], "0x") {
		fmt.Sscanf(m[1], "0x%x", &oldVal)
	} else {
		fmt.Sscanf(m[1], "%d", &oldVal)
	}
	newVal := uint64(0)
	if isSem && oldVal > 0 {
		newVal = oldVal - 1
	}
	newValStr := fmt.Sprintf("0x%x", newVal)
	if newVal == 0 {
		newValStr = "0"
	}
	fdMap[key] = re.ReplaceAllString(target, "eventfd-count="+newValStr)
}

func updateOpenedPathFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, targetPid int, fdMap map[string]string) {
	if eventRaw.Ret < 0 || (scMeta.Name != "open" && scMeta.Name != "openat" && scMeta.Name != "openat2" && scMeta.Name != "creat") {
		return
	}
	path := rawStrArg
	if path == "" || strings.HasPrefix(path, "0x") || path == "NULL" {
		return
	}
	if strings.HasPrefix(path, `"`) && strings.HasSuffix(path, `"`) {
		path = path[1 : len(path)-1]
	}
	fdMap[fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Ret))] = path
}

func updateDupFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if eventRaw.Ret < 0 || (scMeta.Name != "dup" && scMeta.Name != "dup2" && scMeta.Name != "dup3") {
		return
	}
	oldFd := int32(eventRaw.Args[0])
	if path, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, oldFd)]; ok {
		fdMap[fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Ret))] = path
	}
}

func updatePipeFDMapFromPayload(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if eventRaw.Ret != 0 || (scMeta.Name != "pipe" && scMeta.Name != "pipe2") {
		return
	}
	data, ok := fdArrayPayloadData(eventRaw, scMeta, 0)
	if !ok {
		return
	}
	fd1 := int32(binary.LittleEndian.Uint32(data[0:4]))
	fd2 := int32(binary.LittleEndian.Uint32(data[4:8]))
	rememberFDTargetFromProc(eventRaw, targetPid, fd1, "", fdMap)
	rememberFDTargetFromProc(eventRaw, targetPid, fd2, "", fdMap)
}

func updateSocketpairFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if scMeta.Name != "socketpair" || eventRaw.Ret != 0 {
		return
	}
	data, ok := fdArrayPayloadData(eventRaw, scMeta, 3)
	if !ok {
		return
	}
	fd1 := int32(binary.LittleEndian.Uint32(data[0:4]))
	fd2 := int32(binary.LittleEndian.Uint32(data[4:8]))
	info := socketFDInfo(eventRaw)
	rememberFDTargetFromProc(eventRaw, targetPid, fd1, "|"+info, fdMap)
	rememberFDTargetFromProc(eventRaw, targetPid, fd2, "|"+info, fdMap)
}

func fdArrayPayloadData(eventRaw *bpfEvent, scMeta meta.Syscall, argIndex int) ([]byte, bool) {
	for _, section := range payloadSectionsForEvent(eventRaw, scMeta) {
		if section.Kind == handler.PayloadKindStruct &&
			section.Direction == handler.PayloadDirectionOut &&
			section.ArgIndex == argIndex &&
			section.ProbeRet == 0 &&
			len(section.Data) >= fdArrayPayloadSize {
			return section.Data[:fdArrayPayloadSize], true
		}
	}
	return nil, false
}

func updateSocketFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if scMeta.Name != "socket" || eventRaw.Ret < 0 {
		return
	}
	fd := int32(eventRaw.Ret)
	info := socketFDInfo(eventRaw)
	key := fmt.Sprintf("%d:%d", targetPid, fd)
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd))
	if err != nil {
		target = "socket:[]"
	}
	fdMap[key] = target + "|" + info
}

func socketFDInfo(eventRaw *bpfEvent) string {
	info := meta.DecodeFlags(eventRaw.Args[0], "addrfams")
	if eventRaw.Args[0] == 16 {
		info += ":" + meta.DecodeFlags(eventRaw.Args[2], "netlink_protocols")
	}
	return info
}

func updateNetlinkFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if eventRaw.Ret != 0 || (scMeta.Name != "bind" && scMeta.Name != "getsockname") {
		return
	}
	fd := int32(eventRaw.Args[0])
	data, ok := netlinkSockaddrSnapshot(eventRaw, scMeta.Name)
	if !ok || len(data) < 8 || binary.LittleEndian.Uint16(data[0:2]) != 16 {
		return
	}
	nlPid := binary.LittleEndian.Uint32(data[4:8])
	fdMap[fmt.Sprintf("%d:%d", targetPid, fd)] = fmt.Sprintf("NETLINK:[SOCK_DIAG:%d]", nlPid)
}

func netlinkSockaddrSnapshot(eventRaw *bpfEvent, scName string) ([]byte, bool) {
	if scName == "bind" {
		return eventSnapshot(eventRaw, 0, 8, eventRaw.ProbeRetEnter)
	}
	return eventExitSnapshot(eventRaw, handler.BpfExitArgOffset, 8)
}

func updateCwdFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, targetPid int, fdMap map[string]string) {
	if scMeta.Name == "chdir" && eventRaw.Ret == 0 && rawStrArg != "" && !strings.HasPrefix(rawStrArg, "0x") && rawStrArg != "NULL" {
		handler.UpdateCwd(targetPid, rawStrArg, fdMap, int(eventRaw.Pid))
	}
	if scMeta.Name == "fchdir" && eventRaw.Ret == 0 {
		handler.UpdateCwdByFd(targetPid, int32(eventRaw.Args[0]), fdMap)
	}
}

func rememberFDTargetFromProc(eventRaw *bpfEvent, targetPid int, fd int32, suffix string, fdMap map[string]string) {
	key := fmt.Sprintf("%d:%d", targetPid, fd)
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd))
	if err != nil {
		if suffix == "" {
			return
		}
		target = "socket:[]"
	}
	fdMap[key] = target + suffix
}

func eventExitSnapshot(eventRaw *bpfEvent, offset int, size int) ([]byte, bool) {
	return eventSnapshot(eventRaw, offset, size, eventRaw.ProbeRetExit)
}

func eventSnapshot(eventRaw *bpfEvent, offset int, size int, probeRet int32) ([]byte, bool) {
	if probeRet < 0 || offset < 0 || size <= 0 {
		return nil, false
	}
	end := offset + size
	if end < offset || end > len(eventRaw.StrArg) || uint32(end) > eventRaw.DataLen {
		return nil, false
	}
	return eventRaw.StrArg[offset:end], true
}

// IMPACT: checkShouldPrint filters syscall events by syscall list, path and read/write descriptor filter options.
func checkShouldPrint(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, isPath bool, targetPid int, opts *cli.Options, fdMap map[string]string) bool {
	var fds []int32
	for i, argName := range scMeta.Args {
		if isFdArgName(argName) {
			fds = append(fds, int32(eventRaw.Args[i]))
		}
	}
	if len(fds) == 0 {
		fds = []int32{-1}
	}
	matchedPath := event.MatchPath(targetPid, fds, isPath, scMeta.Name, eventRaw.Ptr, rawStrArg, opts.TracePaths, fdMap)
	matchedFD := matchTraceFDs(fds, opts)
	requestedRW := false
	for _, fd := range fds {
		if (scMeta.Name == "read" && opts.TraceReadFDs[fd]) || (scMeta.Name == "write" && opts.TraceWriteFDs[fd]) {
			requestedRW = true
			break
		}
	}

	matchedSyscall := len(opts.TraceSyscalls) == 0 && len(opts.TraceSyscallRegexps) == 0
	if !matchedSyscall {
		if opts.TraceSyscalls[scMeta.Name] {
			matchedSyscall = true
		} else {
			for _, r := range opts.TraceSyscallRegexps {
				if r.MatchString(scMeta.Name) {
					matchedSyscall = true
					break
				}
			}
		}
	}
	if opts.TraceSetIsNegated {
		matchedSyscall = !matchedSyscall
	}
	return matchedSyscall && filtersMatch(matchedPath, matchedFD, requestedRW, opts)
}

func filtersMatch(matchedPath, matchedFD, requestedRW bool, opts *cli.Options) bool {
	hasPathFilter := len(opts.TracePaths) > 0
	hasFDFilter := len(opts.TraceFDs) > 0
	if !hasPathFilter && !hasFDFilter {
		return true
	}
	return (hasPathFilter && matchedPath) || (hasFDFilter && matchedFD) || requestedRW
}

func matchTraceFDs(fds []int32, opts *cli.Options) bool {
	if len(opts.TraceFDs) == 0 {
		return false
	}
	hasValidFD := false
	matchesSet := false
	matchesNegatedSet := false
	for _, fd := range fds {
		if fd < 0 {
			continue
		}
		hasValidFD = true
		if opts.TraceFDs[fd] {
			matchesSet = true
		} else {
			matchesNegatedSet = true
		}
	}
	if opts.TraceFDsNegated {
		return hasValidFD && matchesNegatedSet
	}
	return matchesSet
}

func isFdArgName(name string) bool {
	switch name {
	case "fd", "dfd", "fildes", "oldfd", "newfd":
		return true
	}
	return strings.HasSuffix(name, "fd") || strings.HasSuffix(name, "_fd")
}

func isFdReturnSyscall(scName string) bool {
	if scName == "socketpair" {
		return false
	}
	return strings.HasPrefix(scName, "open") ||
		strings.HasPrefix(scName, "dup") ||
		strings.HasPrefix(scName, "socket") ||
		strings.HasPrefix(scName, "accept") ||
		strings.HasPrefix(scName, "eventfd") ||
		strings.HasPrefix(scName, "epoll_create") ||
		scName == "creat" ||
		scName == "timerfd_create" ||
		strings.HasPrefix(scName, "signalfd") ||
		scName == "pidfd_open" ||
		scName == "userfaultfd"
}
