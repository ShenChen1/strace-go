package main

import (
	"encoding/base64"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	iovecSectionElemSize      = 16
	iovecSectionMaxBytes      = 512
	statPayloadStructSize     = 144
	statfsPayloadStructSize   = 120
	pollPayloadFdSize         = 8
	pollPayloadMaxBytes       = 512
	epollPayloadEventSize     = 12
	epollPayloadMaxBytes      = 512
	timespecPayloadStructSize = 16
	archPrctlPayloadOutSize   = 8
	fdArrayPayloadSize        = 8
	offsetPointerPayloadSize  = 8
	robustListPayloadWordSize = 8
	rlimitPayloadStructSize   = 16
	sysinfoPayloadStructSize  = 112
	utsnamePayloadStructSize  = 65 * 6
	waitidSiginfoPayloadSize  = 128
	waitidRusagePayloadSize   = 144
)

type payloadWindowSpec struct {
	kind      handler.PayloadKind
	direction handler.PayloadDirection
	argIndex  int
	offset    int
	userLen   uint32
	maxLen    uint32
	probeRet  int32
}

type structArrayPayloadSpec struct {
	direction  handler.PayloadDirection
	argIndex   int
	countIndex int
	elemSize   int
	maxBytes   int
	offset     int
	probeRet   int32
}

func payloadSectionsForEvent(eventRaw *bpfEvent, scMeta meta.Syscall) []handler.PayloadSection {
	if sections, ok := scalarPayloadSectionsForEvent(eventRaw, scMeta.Name); ok {
		return sections
	}
	if sections, ok := structuredPayloadSectionsForEvent(eventRaw, scMeta.Name); ok {
		return sections
	}
	return nil
}

func scalarPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) ([]handler.PayloadSection, bool) {
	switch scName {
	case "write", "pwrite64":
		userLen := uint32Clamped(eventRaw.Args[2])
		return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
			kind:      handler.PayloadKindBytes,
			direction: handler.PayloadDirectionIn,
			argIndex:  1,
			userLen:   userLen,
			maxLen:    userLen,
			probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 1),
		}), true
	case "read", "pread64":
		if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
			return nil, true
		}
		userLen := uint32Clamped(uint64(eventRaw.Ret))
		return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
			kind:      handler.PayloadKindBytes,
			direction: handler.PayloadDirectionOut,
			argIndex:  1,
			offset:    handler.BpfExitArgOffset,
			userLen:   userLen,
			maxLen:    userLen,
			probeRet:  eventRaw.ProbeRetExit,
		}), true
	case "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "vmsplice":
		return iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset), true
	case "process_vm_readv", "process_vm_writev":
		sections := iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset)
		return append(sections, iovecPayloadSectionFromWindow(eventRaw, 3, 4, handler.BpfMiscArgOffset)...), true
	case "process_madvise":
		return iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset), true
	case "bpf":
		return bpfPayloadSectionsForEvent(eventRaw), true
	case "getcwd":
		return exitBytesPayloadSectionFromRet(eventRaw, 0), true
	case "readlink":
		return exitBytesPayloadSectionFromRet(eventRaw, 1), true
	case "readlinkat":
		return exitBytesPayloadSectionFromRet(eventRaw, 2), true
	case "sendfile":
		return sendfilePayloadSectionsForEvent(eventRaw), true
	case "copy_file_range":
		return copyFileRangePayloadSectionsForEvent(eventRaw), true
	case "pipe", "pipe2":
		return exitStructPayloadSection(eventRaw, 0, fdArrayPayloadSize), true
	case "socketpair":
		return exitStructPayloadSection(eventRaw, 3, fdArrayPayloadSize), true
	case "openat2":
		return openat2PayloadSectionsForEvent(eventRaw), true
	case "execve", "execveat":
		return execPayloadSectionsForEvent(eventRaw, scName), true
	case "rename", "link", "symlink":
		return dualPathPayloadSectionsForEvent(eventRaw, 0, 1), true
	case "symlinkat":
		return dualPathPayloadSectionsForEvent(eventRaw, 0, 2), true
	case "renameat", "renameat2", "linkat":
		return dualPathPayloadSectionsForEvent(eventRaw, 1, 3), true
	case "mount", "umount2", "fsconfig":
		return fsPayloadSectionsForEvent(eventRaw, scName), true
	case "add_key", "request_key":
		return keyPayloadSectionsForEvent(eventRaw, scName), true
	case "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
		"removexattr", "lremovexattr", "fremovexattr", "listxattr", "llistxattr", "flistxattr":
		return xattrPayloadSectionsForEvent(eventRaw, scName), true
	case "ioctl":
		return ioctlPayloadSectionsForEvent(eventRaw), true
	default:
		if argIndex, ok := simplePathPayloadArgIndex(scName); ok {
			return stringPayloadSectionFromWindow(eventRaw, argIndex), true
		}
		return nil, false
	}
}

func structuredPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) ([]handler.PayloadSection, bool) {
	switch scName {
	case "stat", "lstat":
		return exitStructPayloadSection(eventRaw, 1, statPayloadStructSize), true
	case "fstat":
		return exitStructPayloadSection(eventRaw, 1, statPayloadStructSize), true
	case "newfstatat":
		return exitStructPayloadSection(eventRaw, 2, statPayloadStructSize), true
	case "statfs":
		return exitStructPayloadSection(eventRaw, 1, statfsPayloadStructSize), true
	case "fstatfs":
		return exitStructPayloadSection(eventRaw, 1, statfsPayloadStructSize), true
	case "uname":
		return exitStructPayloadSection(eventRaw, 0, utsnamePayloadStructSize), true
	case "sysinfo":
		return exitStructPayloadSection(eventRaw, 0, sysinfoPayloadStructSize), true
	case "getrlimit":
		return exitStructPayloadSection(eventRaw, 1, rlimitPayloadStructSize), true
	case "setrlimit":
		return enterStructPayloadSection(eventRaw, 1, handler.BpfEnterArgOffset, rlimitPayloadStructSize), true
	case "prlimit64":
		return prlimitPayloadSectionsForEvent(eventRaw), true
	case "get_robust_list":
		return robustListPayloadSectionsForEvent(eventRaw), true
	case "clone3":
		return clone3PayloadSectionsForEvent(eventRaw), true
	case "waitid":
		return waitidPayloadSectionsForEvent(eventRaw), true
	case "arch_prctl":
		return exitStructPayloadSection(eventRaw, 1, archPrctlPayloadOutSize), true
	case "capget", "capset":
		return capabilityPayloadSectionsForEvent(eventRaw, scName), true
	case "io_setup", "io_submit", "io_cancel", "io_getevents", "io_pgetevents", "io_pgetevents_time64":
		return aioPayloadSectionsForEvent(eventRaw, scName), true
	case "cachestat":
		return cachestatPayloadSectionsForEvent(eventRaw), true
	case "fcntl", "fcntl64":
		return fcntlPayloadSectionsForEvent(eventRaw), true
	case "prctl":
		return prctlPayloadSectionsForEvent(eventRaw), true
	case "rt_sigaction", "rt_sigprocmask", "rt_sigsuspend":
		return signalPayloadSectionsForEvent(eventRaw, scName), true
	case "clock_gettime", "clock_getres", "clock_settime", "adjtimex", "clock_adjtime",
		"nanosleep", "clock_nanosleep", "gettimeofday", "settimeofday", "getitimer", "setitimer":
		return timePayloadSectionsForEvent(eventRaw, scName), true
	case "futex", "futex_wait", "futex_waitv", "futex_requeue":
		return futexPayloadSectionsForEvent(eventRaw, scName), true
	case "poll":
		return pollPayloadSectionsForEvent(eventRaw, false), true
	case "ppoll":
		return pollPayloadSectionsForEvent(eventRaw, true), true
	case "select", "_newselect":
		return selectPayloadSectionsForEvent(eventRaw), true
	case "epoll_ctl":
		return enterStructPayloadSection(eventRaw, 3, handler.BpfEnterArgOffset, epollPayloadEventSize), true
	case "epoll_wait", "epoll_pwait":
		return exitStructArrayPayloadSectionFromRet(eventRaw, 1, epollPayloadEventSize, epollPayloadMaxBytes), true
	case "epoll_pwait2":
		return epollPwait2PayloadSectionsForEvent(eventRaw), true
	case "connect", "bind":
		return networkSockaddrInPayloadSection(eventRaw, 1, 2, 0), true
	case "sendto":
		return sendtoPayloadSectionsForEvent(eventRaw), true
	case "recvfrom":
		return recvfromPayloadSectionsForEvent(eventRaw), true
	case "accept", "accept4", "getsockname", "getpeername":
		return acceptLikePayloadSectionsForEvent(eventRaw), true
	default:
		return nil, false
	}
}

func pollPayloadSectionsForEvent(eventRaw *bpfEvent, includeTimeout bool) []handler.PayloadSection {
	sections := structArrayPayloadSectionFromArg(eventRaw, structArrayPayloadSpec{
		direction:  handler.PayloadDirectionIn,
		argIndex:   0,
		countIndex: 1,
		elemSize:   pollPayloadFdSize,
		maxBytes:   pollPayloadMaxBytes,
		offset:     handler.BpfEnterArgOffset,
		probeRet:   getArgProbeStatus(eventRaw.ProbeRetEnter, 0),
	})
	if includeTimeout {
		sections = append(sections, enterStructPayloadSection(eventRaw, 2, handler.BpfMiscArgOffset, timespecPayloadStructSize)...)
	}
	if isExitEvent(eventRaw) && eventRaw.Ret > 0 {
		sections = append(sections, structArrayPayloadSectionFromArg(eventRaw, structArrayPayloadSpec{
			direction:  handler.PayloadDirectionOut,
			argIndex:   0,
			countIndex: 1,
			elemSize:   pollPayloadFdSize,
			maxBytes:   pollPayloadMaxBytes,
			offset:     handler.BpfExitArgOffset,
			probeRet:   eventRaw.ProbeRetExit,
		})...)
	}
	return sections
}

func epollPwait2PayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 3, handler.BpfMiscArgOffset, timespecPayloadStructSize)
	if isExitEvent(eventRaw) && eventRaw.Ret > 0 {
		sections = append(sections, exitStructArrayPayloadSectionFromRet(eventRaw, 1, epollPayloadEventSize, epollPayloadMaxBytes)...)
	}
	return sections
}

func structArrayPayloadSectionFromArg(eventRaw *bpfEvent, spec structArrayPayloadSpec) []handler.PayloadSection {
	if spec.countIndex < 0 || spec.countIndex >= len(eventRaw.Args) {
		return nil
	}
	userLen := structArrayUserLen(eventRaw.Args[spec.countIndex], spec.elemSize)
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: spec.direction,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   userLen,
		maxLen:    uint32(spec.maxBytes),
		probeRet:  spec.probeRet,
	})
}

func exitStructArrayPayloadSectionFromRet(eventRaw *bpfEvent, argIndex int, elemSize int, maxBytes int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
		return nil
	}
	userLen := structArrayUserLen(uint64(eventRaw.Ret), elemSize)
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   userLen,
		maxLen:    uint32(maxBytes),
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func structArrayUserLen(count uint64, elemSize int) uint32 {
	if elemSize <= 0 {
		return 0
	}
	if count > uint64(^uint32(0))/uint64(elemSize) {
		return ^uint32(0)
	}
	return uint32(count * uint64(elemSize))
}

func iovecPayloadSectionFromWindow(eventRaw *bpfEvent, argIndex int, countIndex int, offset int) []handler.PayloadSection {
	if countIndex < 0 || countIndex >= len(eventRaw.Args) {
		return nil
	}
	userLen := iovecUserLen(eventRaw.Args[countIndex])
	if userLen == 0 {
		return nil
	}
	maxLen := int(userLen)
	if maxLen > iovecSectionMaxBytes {
		maxLen = iovecSectionMaxBytes
	}
	data, ok := eventPayloadWindow(eventRaw, offset, maxLen)
	if !ok {
		return nil
	}
	section := newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindIovec,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	}, data)
	return []handler.PayloadSection{section}
}

func iovecUserLen(count uint64) uint32 {
	if count > uint64(^uint32(0))/iovecSectionElemSize {
		return ^uint32(0)
	}
	return uint32(count * iovecSectionElemSize)
}

func payloadSectionFromWindowSpec(eventRaw *bpfEvent, spec payloadWindowSpec) []handler.PayloadSection {
	if spec.userLen == 0 {
		return nil
	}
	if spec.maxLen == 0 || spec.maxLen > spec.userLen {
		spec.maxLen = spec.userLen
	}
	data, ok := eventPayloadWindow(eventRaw, spec.offset, int(spec.maxLen))
	if !ok {
		return nil
	}
	section := newPayloadSection(eventRaw, spec, data)
	return []handler.PayloadSection{section}
}

func eventPayloadWindow(eventRaw *bpfEvent, offset int, maxLen int) ([]byte, bool) {
	if offset < 0 || maxLen <= 0 || eventRaw.DataLen == 0 {
		return nil, false
	}
	if uint32(offset) >= eventRaw.DataLen || offset >= len(eventRaw.StrArg) {
		return nil, false
	}
	end := int(eventRaw.DataLen)
	if end > len(eventRaw.StrArg) {
		end = len(eventRaw.StrArg)
	}
	if limit := offset + maxLen; limit < end {
		end = limit
	}
	if end <= offset {
		return nil, false
	}
	return eventRaw.StrArg[offset:end], true
}

func newPayloadSection(eventRaw *bpfEvent, spec payloadWindowSpec, data []byte) handler.PayloadSection {
	section := handler.PayloadSection{
		Kind:      spec.kind,
		Direction: spec.direction,
		ArgIndex:  spec.argIndex,
		Offset:    uint32(spec.offset),
		UserLen:   spec.userLen,
		CopiedLen: uint32(len(data)),
		ProbeRet:  spec.probeRet,
		Data:      data,
	}
	if spec.argIndex >= 0 && spec.argIndex < len(eventRaw.Args) {
		section.UserPtr = eventRaw.Args[spec.argIndex]
	}
	return section
}

func jsonPayloadSections(sections []handler.PayloadSection) []jsonPayloadSection {
	if len(sections) == 0 {
		return nil
	}
	out := make([]jsonPayloadSection, 0, len(sections))
	for _, section := range sections {
		out = append(out, jsonPayloadSection{
			Kind:       string(section.Kind),
			Direction:  string(section.Direction),
			ArgIndex:   section.ArgIndex,
			Offset:     section.Offset,
			UserPtr:    section.UserPtr,
			UserLen:    section.UserLen,
			CopiedLen:  section.CopiedLen,
			ProbeRet:   section.ProbeRet,
			DataBase64: base64.StdEncoding.EncodeToString(section.Data),
		})
	}
	return out
}

func uint32Clamped(v uint64) uint32 {
	if v > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}
