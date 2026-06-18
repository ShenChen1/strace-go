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
func updateFDMap(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, decoder *event.Decoder, targetPid int, fdMap map[string]string) {
	ret := eventRaw.Ret
	strArgBuf := eventRaw.StrArg[:]
	if ret >= 0 && isFdReturnSyscall(scMeta.Name) {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Pid, ret)
		target, err := os.Readlink(linkPath)
		if err == nil {
			if strings.HasPrefix(target, "anon_inode:[eventfd]") {
				forceCount := (scMeta.Name == "eventfd" || scMeta.Name == "eventfd2")
				flags := uint64(0)
				if len(eventRaw.Args) > 1 {
					flags = eventRaw.Args[1]
				}
				if info := handler.FormatEventfdInfo(linkPath, uint64(uint32(eventRaw.Args[0])), flags, forceCount); info != "" {
					target = info
				}
			}
			fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = target
		} else if scMeta.Name == "eventfd" || scMeta.Name == "eventfd2" {
			flags := uint64(0)
			if len(eventRaw.Args) > 1 {
				flags = eventRaw.Args[1]
			}
			if info := handler.FormatEventfdInfo(linkPath, uint64(uint32(eventRaw.Args[0])), flags, true); info != "" {
				fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = info
			}
		}
	}
	if scMeta.Name == "read" && ret == 8 {
		fd := int32(eventRaw.Args[0])
		key := fmt.Sprintf("%d:%d", targetPid, fd)
		if target, ok := fdMap[key]; ok && strings.Contains(target, "eventfd-count=") {
			isSem := strings.Contains(target, "eventfd-semaphore=1")
			re := regexp.MustCompile(`eventfd-count=([^,]+)`)
			m := re.FindStringSubmatch(target)
			if len(m) == 2 {
				oldValStr := m[1]
				var oldVal uint64
				if strings.HasPrefix(oldValStr, "0x") {
					fmt.Sscanf(oldValStr, "0x%x", &oldVal)
				} else {
					fmt.Sscanf(oldValStr, "%d", &oldVal)
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
		}
	}
	if scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" {
		if ret >= 0 {
			p := rawStrArg
			if scMeta.Name == "openat" || scMeta.Name == "openat2" {
				// IMPACT: Use Tid instead of Pid to guarantee process_vm_readv succeeds even if leader thread is zombie.
				p = decoder.DecodeString(int(eventRaw.Tid), eventRaw.Args[1], strArgBuf, eventRaw.ProbeRetEnter, scMeta.Name, 0)
			}
			if p != "" && !strings.HasPrefix(p, "0x") && p != "NULL" {
				if strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`) {
					p = p[1 : len(p)-1]
				}
				fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = p
			}
		}
	}
	if (scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3") && ret >= 0 {
		oldFd := int32(eventRaw.Args[0])
		if p, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, oldFd)]; ok {
			fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = p
		}
	}
	// Deletion for "close" is deferred to the end of handleEvent to ensure DecodeFd still has the state.
	if (scMeta.Name == "pipe" || scMeta.Name == "pipe2") && ret == 0 {
		if d, err := decoder.MemReader.ReadRobust(int(eventRaw.Tid), eventRaw.Args[0], 8, true); err == nil && len(d) >= 8 {
			fd1 := int32(binary.LittleEndian.Uint32(d[0:4]))
			fd2 := int32(binary.LittleEndian.Uint32(d[4:8]))
			if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd1)); err == nil {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd1)] = target
			}
			if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd2)); err == nil {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd2)] = target
			}
		}
	}
	if scMeta.Name == "socketpair" && ret == 0 {
		if d, err := decoder.MemReader.ReadRobust(int(eventRaw.Tid), eventRaw.Args[3], 8, true); err == nil && len(d) >= 8 {
			fd1 := int32(binary.LittleEndian.Uint32(d[0:4]))
			fd2 := int32(binary.LittleEndian.Uint32(d[4:8]))
			domain := eventRaw.Args[0]
			proto := eventRaw.Args[2]
			info := meta.DecodeFlags(domain, "addrfams")
			if domain == 16 {
				info += ":" + meta.DecodeFlags(proto, "netlink_protocols")
			}

			if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd1)); err == nil {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd1)] = target + "|" + info
			} else {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd1)] = "socket:[]|" + info
			}
			if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, fd2)); err == nil {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd2)] = target + "|" + info
			} else {
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd2)] = "socket:[]|" + info
			}
		}
	}
	if (scMeta.Name == "socket") && ret >= 0 {
		domain := eventRaw.Args[0]
		proto := eventRaw.Args[2]
		info := meta.DecodeFlags(domain, "addrfams")
		if domain == 16 {
			info += ":" + meta.DecodeFlags(proto, "netlink_protocols")
		}

		key := fmt.Sprintf("%d:%d", targetPid, int32(ret))
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", eventRaw.Tid, int32(ret)))
		if err != nil {
			target = "socket:[]"
		}
		fdMap[key] = target + "|" + info
	}
	if (scMeta.Name == "bind" || scMeta.Name == "getsockname") && ret == 0 {
		fd := int32(eventRaw.Args[0])
		ptr := eventRaw.Args[1]
		if d, err := decoder.MemReader.ReadRobust(int(eventRaw.Pid), ptr, 12, true); err == nil && len(d) >= 8 {
			family := binary.LittleEndian.Uint16(d[0:2])
			if family == 16 { // AF_NETLINK
				nlPid := binary.LittleEndian.Uint32(d[4:8])
				fdMap[fmt.Sprintf("%d:%d", targetPid, fd)] = fmt.Sprintf("NETLINK:[SOCK_DIAG:%d]", nlPid)
			}
		}
	}
	// IMPACT: Keep tracee's tracked working directory state updated in fdMap to resolve AT_FDCWD correctly under fast timing races.
	if scMeta.Name == "chdir" && ret == 0 {
		p := rawStrArg
		if p != "" && !strings.HasPrefix(p, "0x") && p != "NULL" {
			handler.UpdateCwd(targetPid, p, fdMap, int(eventRaw.Pid))
		}
	}
	if scMeta.Name == "fchdir" && ret == 0 {
		handler.UpdateCwdByFd(targetPid, int32(eventRaw.Args[0]), fdMap)
	}
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
	for _, fd := range fds {
		if fd < 0 {
			continue
		}
		hasValidFD = true
		if opts.TraceFDs[fd] {
			matchesSet = true
		}
	}
	if opts.TraceFDsNegated {
		return hasValidFD && !matchesSet
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
