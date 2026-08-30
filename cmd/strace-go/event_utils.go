package main

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func updateFdReturnMapFromSource(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	view := src.view
	if !view.valid || view.ret < 0 {
		return
	}
	policy, ok := fdCreatorPolicyFor(scMeta.Name, view)
	if !ok {
		return
	}
	if !hasFDStateSnapshotForFD(src, int32(view.ret)) {
		delete(fdMap, fdStateKey(targetPid, int32(view.ret)))
		return
	}
	state := policy.state(src)
	key := fdStateKey(targetPid, int32(view.ret))
	if !state.pathKnown {
		delete(fdMap, key)
		return
	}
	fdMap[key] = state.path
}

func updateEventfdCountFromView(view syscallEventView, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if !view.valid || scMeta.Name != "read" || view.ret != 8 {
		return
	}
	fd := int32(view.args[0])
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

func updateOpenedPathFDMapFromView(view syscallEventView, scMeta meta.Syscall, pathText string, targetPid int, fdMap map[string]string) {
	if !view.valid || view.ret < 0 || !isOpenedPathFDStateSyscall(scMeta.Name) {
		return
	}
	path := openedPathStateTarget(view, scMeta.Name, pathText, targetPid, fdMap)
	if path == "" {
		return
	}
	fdMap[fmt.Sprintf("%d:%d", targetPid, int32(view.ret))] = path
}

func openedPathStateTarget(view syscallEventView, scName string, pathText string, targetPid int, fdMap map[string]string) string {
	if pathText == "" || strings.HasPrefix(pathText, "0x") || pathText == "NULL" {
		return ""
	}
	path := strings.TrimSuffix(strings.TrimPrefix(pathText, `"`), `"`)
	if path != "" || scName != "open_tree" {
		return path
	}
	dfd := int32(view.args[0])
	if dfd == handler.AtFdcwd {
		return fdMap[fmt.Sprintf("%d:cwd", targetPid)]
	}
	return fdMap[fmt.Sprintf("%d:%d", targetPid, dfd)]
}

func isOpenedPathFDStateSyscall(scName string) bool {
	switch scName {
	case "open", "openat", "openat2", "open_tree", "creat":
		return true
	default:
		return false
	}
}

func updateDupFDMapFromSource(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	oldFd, newFd, ok := duplicatedFDsFromView(src.view, scMeta)
	if !ok {
		return
	}
	newKey := fmt.Sprintf("%d:%d", targetPid, newFd)
	if oldFd != newFd {
		delete(fdMap, newKey)
	}
	if isFcntlFDStateSyscall(scMeta.Name) && !hasFDStateSnapshotForFD(src, newFd) {
		return
	}
	if path, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, oldFd)]; ok {
		fdMap[newKey] = path
	}
}

func duplicatedFDsFromView(view syscallEventView, scMeta meta.Syscall) (int32, int32, bool) {
	if !view.valid || view.ret < 0 {
		return 0, 0, false
	}
	switch scMeta.Name {
	case "dup", "dup2", "dup3":
		return int32(view.args[0]), int32(view.ret), true
	case "fcntl", "fcntl64":
		if isFcntlFDStateCommand(view.args) {
			return int32(view.args[0]), int32(view.ret), true
		}
	}
	return 0, 0, false
}

func hasFDStateSnapshotForFD(src fdStateSource, fd int32) bool {
	for _, section := range src.payloadSections {
		observation, ok := fdStateObservationFromSection(section)
		if ok && observation.FD == fd {
			return true
		}
	}
	return false
}

func updatePipeFDMapFromPayload(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if !src.view.valid || src.view.ret != 0 || (scMeta.Name != "pipe" && scMeta.Name != "pipe2") {
		return
	}
	data, ok := fdArrayPayloadData(src.payloadSections, 0)
	if !ok {
		return
	}
	fd1 := int32(binary.LittleEndian.Uint32(data[0:4]))
	fd2 := int32(binary.LittleEndian.Uint32(data[4:8]))
	rememberFDTarget(targetPid, fd1, "pipe:[unknown]", fdMap)
	rememberFDTarget(targetPid, fd2, "pipe:[unknown]", fdMap)
}

func updateSocketpairFDMap(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string, flagDecoder fdFlagDecoder) {
	if !src.view.valid || scMeta.Name != "socketpair" || src.view.ret != 0 {
		return
	}
	data, ok := fdArrayPayloadData(src.payloadSections, 3)
	if !ok {
		return
	}
	fd1 := int32(binary.LittleEndian.Uint32(data[0:4]))
	fd2 := int32(binary.LittleEndian.Uint32(data[4:8]))
	info := socketFDInfoFromFlags(flagDecoder, src.view)
	rememberFDTarget(targetPid, fd1, "socket:[unknown]|"+info, fdMap)
	rememberFDTarget(targetPid, fd2, "socket:[unknown]|"+info, fdMap)
}

func fdArrayPayloadData(sections []handler.PayloadSection, argIndex int) ([]byte, bool) {
	for _, section := range sections {
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

func updateSocketFDMapFromSource(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string, flagDecoder fdFlagDecoder) {
	view := src.view
	if !view.valid || scMeta.Name != "socket" || view.ret < 0 {
		return
	}
	fd := int32(view.ret)
	info := socketFDInfoFromFlags(flagDecoder, view)
	inode := "unknown"
	for _, section := range src.payloadSections {
		observation, ok := fdStateObservationFromSection(section)
		if ok && observation.FD == fd && observation.Inode != 0 {
			inode = fmt.Sprintf("%d", observation.Inode)
			break
		}
	}
	key := fmt.Sprintf("%d:%d", targetPid, fd)
	fdMap[key] = "socket:[" + inode + "]|" + info
}

func socketFDInfoFromFlags(flagDecoder fdFlagDecoder, view syscallEventView) string {
	if flagDecoder == nil {
		return ""
	}
	info := flagDecoder.DecodeFlags(view.args[0], "addrfams")
	if view.args[0] == 16 {
		info += ":" + flagDecoder.DecodeFlags(view.args[2], "netlink_protocols")
	}
	return info
}

func updateNetlinkFDMap(src fdStateSource, scMeta meta.Syscall, targetPid int, fdMap map[string]string) {
	if !src.view.valid || src.view.ret != 0 || (scMeta.Name != "bind" && scMeta.Name != "getsockname") {
		return
	}
	fd := int32(src.view.args[0])
	data, ok := netlinkSockaddrPayload(src, scMeta)
	if !ok || len(data) < 8 || binary.LittleEndian.Uint16(data[0:2]) != 16 {
		return
	}
	nlPid := binary.LittleEndian.Uint32(data[4:8])
	fdMap[fmt.Sprintf("%d:%d", targetPid, fd)] = fmt.Sprintf(
		"socket:[SOCK_DIAG:%d]|AF_NETLINK:NETLINK_SOCK_DIAG",
		nlPid,
	)
}

func netlinkSockaddrPayload(src fdStateSource, scMeta meta.Syscall) ([]byte, bool) {
	if src.view.eventType != bpfEventTypeEnter && src.view.eventType != bpfEventTypeExit {
		return nil, false
	}
	direction := handler.PayloadDirectionIn
	if scMeta.Name == "getsockname" {
		direction = handler.PayloadDirectionOut
	}
	for _, section := range src.payloadSections {
		if section.Kind == handler.PayloadKindStruct &&
			section.Direction == direction &&
			section.ArgIndex == 1 &&
			section.ProbeRet == 0 &&
			len(section.Data) >= 8 {
			return section.Data[:8], true
		}
	}
	return nil, false
}

func rememberFDTarget(targetPid int, fd int32, target string, fdMap map[string]string) {
	key := fmt.Sprintf("%d:%d", targetPid, fd)
	fdMap[key] = target
}

type printFilterRequest struct {
	view            syscallEventView
	scMeta          meta.Syscall
	pathArguments   []event.PathArgument
	targetPid       int
	filter          traceFilterOptions
	fdState         event.FDPathReader
	eventFD         event.EventFDPathReader
	payloadSections []handler.PayloadSection
}

func checkShouldPrintFromView(req printFilterRequest) bool {
	fds := req.candidateFDs()
	matchedPath := event.MatchPath(req.pathMatchRequest(fds))
	matchedFD := req.filter.MatchFDs(fds)
	return req.matchesSyscallSet() && filtersMatch(matchedPath, matchedFD, req.matchesReadWriteFD(fds), req.filter)
}

func (req printFilterRequest) candidateFDs() []int32 {
	var fds []int32
	for i, argName := range req.scMeta.Args {
		if req.scMeta.Name == "fsconfig" && i == 0 {
			continue
		}
		if isFdArgName(argName) {
			fds = append(fds, int32(req.view.args[i]))
		}
	}
	fds = append(fds, payloadSectionFDs(req.scMeta.Name, req.view.args, req.payloadSections)...)
	if len(fds) == 0 {
		fds = []int32{-1}
	}
	return fds
}

func (req printFilterRequest) pathMatchRequest(fds []int32) event.PathMatchRequest {
	return event.PathMatchRequest{
		Pid:           req.targetPid,
		FDs:           fds,
		PathArguments: req.pathArguments,
		TracePaths:    req.filter.PathFilter(),
		FDState:       req.fdState,
		EventFD:       req.eventFD,
	}
}

func (req printFilterRequest) matchesReadWriteFD(fds []int32) bool {
	for _, fd := range fds {
		if (req.scMeta.Name == "read" && req.filter.TraceReadFD(fd)) ||
			(req.scMeta.Name == "write" && req.filter.TraceWriteFD(fd)) {
			return true
		}
	}
	return false
}

func (req printFilterRequest) matchesSyscallSet() bool {
	return req.filter.MatchSyscall(req.scMeta.Name)
}

func payloadSectionFDs(syscallName string, args [6]uint64, payloadSections []handler.PayloadSection) []int32 {
	fds := pollPayloadFDs(syscallName, payloadSections)
	fds = append(fds, selectPayloadFDs(syscallName, args, payloadSections)...)
	fds = append(fds, fsconfigPayloadFDs(syscallName, args)...)
	return fds
}

func fsconfigPayloadFDs(syscallName string, args [6]uint64) []int32 {
	if syscallName != "fsconfig" {
		return nil
	}
	switch uint32(args[1]) {
	case 3, 4, 5:
		return []int32{int32(args[4])}
	default:
		return nil
	}
}

func pollPayloadFDs(syscallName string, payloadSections []handler.PayloadSection) []int32 {
	if syscallName != "poll" && syscallName != "ppoll" {
		return nil
	}
	for _, section := range payloadSections {
		if section.Kind != handler.PayloadKindStruct ||
			section.Direction != handler.PayloadDirectionIn ||
			section.ArgIndex != 0 ||
			section.ProbeRet != 0 {
			continue
		}
		return pollFDsFromData(section.Data)
	}
	return nil
}

func pollFDsFromData(data []byte) []int32 {
	if len(data) < pollPayloadFdSize {
		return nil
	}
	fds := make([]int32, 0, len(data)/pollPayloadFdSize)
	for off := 0; off+pollPayloadFdSize <= len(data); off += pollPayloadFdSize {
		fds = append(fds, int32(binary.LittleEndian.Uint32(data[off:off+4])))
	}
	return fds
}

func selectPayloadFDs(syscallName string, args [6]uint64, payloadSections []handler.PayloadSection) []int32 {
	if syscallName != "select" && syscallName != "_newselect" {
		return nil
	}
	nfds := int(int32(args[0]))
	if nfds <= 0 {
		return nil
	}
	fds := []int32{}
	for _, section := range payloadSections {
		if !isSelectFdSetPayload(section) {
			continue
		}
		fds = append(fds, selectFDsFromData(section.Data, nfds)...)
	}
	return fds
}

func isSelectFdSetPayload(section handler.PayloadSection) bool {
	return section.Kind == handler.PayloadKindBytes &&
		section.Direction == handler.PayloadDirectionIn &&
		section.ArgIndex >= selectPayloadFdSetArgBase &&
		section.ArgIndex <= selectPayloadFdSetArgLast &&
		section.ProbeRet == 0
}

func selectFDsFromData(data []byte, nfds int) []int32 {
	maxFD := nfds
	if maxFD > len(data)*8 {
		maxFD = len(data) * 8
	}
	if maxFD > selectPayloadFdSetSize*8 {
		maxFD = selectPayloadFdSetSize * 8
	}
	fds := []int32{}
	for fd := 0; fd < maxFD; fd++ {
		if data[fd/8]&(1<<uint(fd%8)) != 0 {
			fds = append(fds, int32(fd))
		}
	}
	return fds
}

func filtersMatch(matchedPath, matchedFD, requestedRW bool, filter traceFilterOptions) bool {
	pathFilter := filter.PathFilter()
	hasPathFilter := pathFilter != nil && !pathFilter.Empty()
	hasFDFilter := filter.HasFDFilter()
	if !hasPathFilter && !hasFDFilter {
		return true
	}
	return (hasPathFilter && matchedPath) || (hasFDFilter && matchedFD) || requestedRW
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
		scName == "inotify_init" || scName == "inotify_init1" ||
		scName == "creat" ||
		scName == "timerfd_create" ||
		strings.HasPrefix(scName, "signalfd") ||
		scName == "pidfd_open" ||
		scName == "userfaultfd"
}
