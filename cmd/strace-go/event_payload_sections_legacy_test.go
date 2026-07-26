package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	iovecSectionElemSize      = 16
	iovecSectionMaxBytes      = 512
	memfdNamePayloadMaxBytes  = 250
	statPayloadStructSize     = 144
	statfsPayloadStructSize   = 120
	pollPayloadMaxBytes       = 512
	epollPayloadEventSize     = 12
	epollPayloadMaxBytes      = 512
	timespecPayloadStructSize = 16
	archPrctlPayloadOutSize   = 8
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

type payloadSourceSectionRule func(event payloadEvent, scName string) []handler.PayloadSection

var payloadSourceSectionRules = map[string]payloadSourceSectionRule{
	"readv":    iovecArgPayloadSectionsFromSource,
	"writev":   iovecArgPayloadSectionsFromSource,
	"preadv":   iovecArgPayloadSectionsFromSource,
	"pwritev":  iovecArgPayloadSectionsFromSource,
	"preadv2":  iovecArgPayloadSectionsFromSource,
	"pwritev2": iovecArgPayloadSectionsFromSource,
	"vmsplice": iovecArgPayloadSectionsFromSource,

	"process_vm_readv":  processVMPayloadSectionsFromSource,
	"process_vm_writev": processVMPayloadSectionsFromSource,
	"process_madvise":   processMadvisePayloadSectionsFromSource,

	"rename":    dualPathPayloadSourceRule(0, 1),
	"link":      dualPathPayloadSourceRule(0, 1),
	"symlink":   dualPathPayloadSourceRule(0, 1),
	"symlinkat": dualPathPayloadSourceRule(0, 2),
	"renameat":  dualPathPayloadSourceRule(1, 3),
	"renameat2": dualPathPayloadSourceRule(1, 3),
	"linkat":    dualPathPayloadSourceRule(1, 3),

	"memfd_create": memfdCreatePayloadSectionsFromSource,
	"openat2":      openat2PayloadSectionsFromSource,
	"sendfile":     sendfilePayloadSectionsFromSource,

	"getcwd":     exitBytesPayloadSourceRule(0),
	"getdents64": exitBytesPayloadSourceRule(1),
	"readlink":   exitBytesPayloadSourceRule(1),
	"readlinkat": exitBytesPayloadSourceRule(2),
	"pipe":       exitStructPayloadSourceRule(0, fdArrayPayloadSize),
	"pipe2":      exitStructPayloadSourceRule(0, fdArrayPayloadSize),
	"socketpair": exitStructPayloadSourceRule(3, fdArrayPayloadSize),

	"stat":       exitStructPayloadSourceRule(1, statPayloadStructSize),
	"lstat":      exitStructPayloadSourceRule(1, statPayloadStructSize),
	"fstat":      exitStructPayloadSourceRule(1, statPayloadStructSize),
	"newfstatat": exitStructPayloadSourceRule(2, statPayloadStructSize),
	"statfs":     exitStructPayloadSourceRule(1, statfsPayloadStructSize),
	"fstatfs":    exitStructPayloadSourceRule(1, statfsPayloadStructSize),
	"uname":      exitStructPayloadSourceRule(0, utsnamePayloadStructSize),
	"sysinfo":    exitStructPayloadSourceRule(0, sysinfoPayloadStructSize),
	"getrlimit":  exitStructPayloadSourceRule(1, rlimitPayloadStructSize),
	"setrlimit":  enterStructPayloadSourceRule(1, payloadEnterArgOffset, rlimitPayloadStructSize),
	"prlimit64":  prlimitPayloadSectionsFromSource,
	"arch_prctl": exitStructPayloadSourceRule(1, archPrctlPayloadOutSize),

	"get_robust_list": robustListPayloadSectionsFromSource,
	"waitid":          waitidPayloadSectionsFromSource,

	"copy_file_range":      copyFileRangePayloadSectionsFromSource,
	"clone3":               clone3PayloadSectionsFromSource,
	"cachestat":            cachestatPayloadSectionsFromSource,
	"capget":               capabilityPayloadSectionsFromSource,
	"capset":               capabilityPayloadSectionsFromSource,
	"fcntl":                fcntlPayloadSectionsFromSource,
	"fcntl64":              fcntlPayloadSectionsFromSource,
	"prctl":                prctlPayloadSectionsFromSource,
	"rt_sigaction":         signalPayloadSectionsFromSource,
	"rt_sigprocmask":       signalPayloadSectionsFromSource,
	"rt_sigsuspend":        signalPayloadSectionsFromSource,
	"poll":                 pollPayloadSourceRule(false),
	"ppoll":                pollPayloadSourceRule(true),
	"select":               selectPayloadSectionsFromSource,
	"_newselect":           selectPayloadSectionsFromSource,
	"epoll_ctl":            enterStructPayloadSourceRule(3, payloadEnterArgOffset, epollPayloadEventSize),
	"epoll_wait":           exitStructArrayPayloadSourceRule(1, epollPayloadEventSize, epollPayloadMaxBytes),
	"epoll_pwait":          exitStructArrayPayloadSourceRule(1, epollPayloadEventSize, epollPayloadMaxBytes),
	"epoll_pwait2":         epollPwait2PayloadSectionsFromSource,
	"futex":                futexPayloadSectionsFromSource,
	"futex_wait":           futexPayloadSectionsFromSource,
	"futex_waitv":          futexPayloadSectionsFromSource,
	"futex_requeue":        futexPayloadSectionsFromSource,
	"add_key":              keyPayloadSectionsFromSource,
	"request_key":          keyPayloadSectionsFromSource,
	"setxattr":             xattrPayloadSectionsFromSource,
	"lsetxattr":            xattrPayloadSectionsFromSource,
	"fsetxattr":            xattrPayloadSectionsFromSource,
	"getxattr":             xattrPayloadSectionsFromSource,
	"lgetxattr":            xattrPayloadSectionsFromSource,
	"fgetxattr":            xattrPayloadSectionsFromSource,
	"removexattr":          xattrPayloadSectionsFromSource,
	"lremovexattr":         xattrPayloadSectionsFromSource,
	"fremovexattr":         xattrPayloadSectionsFromSource,
	"listxattr":            xattrPayloadSectionsFromSource,
	"llistxattr":           xattrPayloadSectionsFromSource,
	"flistxattr":           xattrPayloadSectionsFromSource,
	"mount":                fsPayloadSectionsFromSource,
	"umount2":              fsPayloadSectionsFromSource,
	"fsconfig":             fsPayloadSectionsFromSource,
	"bpf":                  bpfPayloadSectionsFromSource,
	"clock_gettime":        timePayloadSectionsFromSource,
	"clock_getres":         timePayloadSectionsFromSource,
	"clock_settime":        timePayloadSectionsFromSource,
	"adjtimex":             timePayloadSectionsFromSource,
	"clock_adjtime":        timePayloadSectionsFromSource,
	"nanosleep":            timePayloadSectionsFromSource,
	"clock_nanosleep":      timePayloadSectionsFromSource,
	"gettimeofday":         timePayloadSectionsFromSource,
	"settimeofday":         timePayloadSectionsFromSource,
	"getitimer":            timePayloadSectionsFromSource,
	"setitimer":            timePayloadSectionsFromSource,
	"utime":                timePayloadSectionsFromSource,
	"utimes":               timePayloadSectionsFromSource,
	"futimesat":            timePayloadSectionsFromSource,
	"utimensat":            timePayloadSectionsFromSource,
	"connect":              networkSockaddrInPayloadSourceRule(1, 2, 0),
	"bind":                 networkSockaddrInPayloadSourceRule(1, 2, 0),
	"sendto":               sendtoPayloadSectionsFromSource,
	"recvfrom":             recvfromPayloadSectionsFromSource,
	"accept":               acceptLikePayloadSectionsFromSource,
	"accept4":              acceptLikePayloadSectionsFromSource,
	"getsockname":          acceptLikePayloadSectionsFromSource,
	"getpeername":          acceptLikePayloadSectionsFromSource,
	"io_setup":             aioPayloadSectionsFromSource,
	"io_submit":            aioPayloadSectionsFromSource,
	"io_cancel":            aioPayloadSectionsFromSource,
	"io_getevents":         aioPayloadSectionsFromSource,
	"io_pgetevents":        aioPayloadSectionsFromSource,
	"io_pgetevents_time64": aioPayloadSectionsFromSource,
	"ioctl":                ioctlPayloadSectionsFromSource,
}

func payloadSectionsForPayloadEvent(event payloadEvent, scMeta meta.Syscall) []handler.PayloadSection {
	if !event.IsSyscallEvent() {
		return nil
	}
	if rule, ok := payloadSourceSectionRules[scMeta.Name]; ok {
		return rule(event, scMeta.Name)
	}
	if argIndex, ok := simplePathPayloadArgIndex(scMeta.Name); ok {
		return stringPayloadSectionFromSource(event, argIndex)
	}
	return nil
}

func exitBytesPayloadSourceRule(argIndex int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return exitBytesPayloadSectionFromSourceRet(event, argIndex)
	}
}

func exitStructPayloadSourceRule(argIndex int, size uint32) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return exitStructPayloadSectionFromSource(event, argIndex, size)
	}
}

func enterStructPayloadSourceRule(argIndex int, offset int, size uint32) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return enterStructPayloadSectionFromSource(event, argIndex, offset, size)
	}
}

func dualPathPayloadSourceRule(firstArg int, secondArg int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return dualPathPayloadSectionsFromSource(event, firstArg, secondArg)
	}
}

func exitStructArrayPayloadSourceRule(argIndex int, elemSize int, maxBytes int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return exitStructArrayPayloadSectionFromSourceRet(event, argIndex, elemSize, maxBytes)
	}
}

func pollPayloadSourceRule(includeTimeout bool) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return pollPayloadSectionsFromSource(event, includeTimeout)
	}
}

func networkSockaddrInPayloadSourceRule(argIndex int, lenIndex int, offset int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return networkSockaddrInPayloadSection(event, argIndex, lenIndex, offset)
	}
}

func memfdCreatePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: 0,
		maxBytes: memfdNamePayloadMaxBytes,
	})
}

func pollPayloadSectionsFromSource(event payloadEvent, includeTimeout bool) []handler.PayloadSection {
	sections := structArrayPayloadSectionFromSourceArg(event, structArrayPayloadSpec{
		direction:  handler.PayloadDirectionIn,
		argIndex:   0,
		countIndex: 1,
		elemSize:   pollPayloadFdSize,
		maxBytes:   pollPayloadMaxBytes,
		offset:     payloadEnterArgOffset,
		probeRet:   event.ProbeRetEnterArg(0),
	})
	if includeTimeout {
		sections = append(sections, enterStructPayloadSectionFromSource(event, 2, payloadMiscArgOffset, timespecPayloadStructSize)...)
	}
	if event.IsExit() && event.Ret() > 0 {
		sections = append(sections, structArrayPayloadSectionFromSourceArg(event, structArrayPayloadSpec{
			direction:  handler.PayloadDirectionOut,
			argIndex:   0,
			countIndex: 1,
			elemSize:   pollPayloadFdSize,
			maxBytes:   pollPayloadMaxBytes,
			offset:     payloadExitArgOffset,
			probeRet:   event.ProbeRetExit(),
		})...)
	}
	return sections
}

func epollPwait2PayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 3, payloadMiscArgOffset, timespecPayloadStructSize)
	if event.IsExit() && event.Ret() > 0 {
		sections = append(sections, exitStructArrayPayloadSectionFromSourceRet(event, 1, epollPayloadEventSize, epollPayloadMaxBytes)...)
	}
	return sections
}

func structArrayPayloadSectionFromSourceArg(event payloadEvent, spec structArrayPayloadSpec) []handler.PayloadSection {
	if spec.countIndex < 0 || spec.countIndex >= 6 {
		return nil
	}
	count := event.Arg(spec.countIndex)
	userLen := structArrayUserLen(count, spec.elemSize)
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: spec.direction,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   userLen,
		maxLen:    uint32(spec.maxBytes),
		probeRet:  spec.probeRet,
	})
}

func exitStructArrayPayloadSectionFromSourceRet(
	event payloadEvent,
	argIndex int,
	elemSize int,
	maxBytes int,
) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() <= 0 {
		return nil
	}
	userLen := structArrayUserLen(uint64(event.Ret()), elemSize)
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    payloadExitArgOffset,
		userLen:   userLen,
		maxLen:    uint32(maxBytes),
		probeRet:  event.ProbeRetExit(),
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

func iovecUserLen(count uint64) uint32 {
	if count > uint64(^uint32(0))/iovecSectionElemSize {
		return ^uint32(0)
	}
	return uint32(count * iovecSectionElemSize)
}

func payloadSectionFromSourceSpec(source payloadSource, spec payloadWindowSpec) []handler.PayloadSection {
	if source == nil || spec.userLen == 0 {
		return nil
	}
	if spec.maxLen == 0 || spec.maxLen > spec.userLen {
		spec.maxLen = spec.userLen
	}
	data, ok := source.PayloadWindow(spec.offset, int(spec.maxLen))
	if !ok {
		return nil
	}
	section := newPayloadSectionFromSource(source, spec, data)
	return []handler.PayloadSection{section}
}

func newPayloadSectionFromSource(source payloadSource, spec payloadWindowSpec, data []byte) handler.PayloadSection {
	section := handler.PayloadSection{
		Kind:      spec.kind,
		Direction: spec.direction,
		ArgIndex:  spec.argIndex,
		UserLen:   spec.userLen,
		CopiedLen: uint32(len(data)),
		ProbeRet:  spec.probeRet,
		Data:      data,
	}
	if userPtr, ok := source.Arg(spec.argIndex); ok {
		section.UserPtr = userPtr
	}
	return section
}

func uint32Clamped(v uint64) uint32 {
	if v > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}
