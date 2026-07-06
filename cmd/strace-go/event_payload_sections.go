package main

import (
	"encoding/base64"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	iovecSectionElemSize      = 16
	iovecSectionMaxBytes      = 512
	memfdNamePayloadMaxBytes  = 250
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

type payloadSectionRule func(eventRaw *bpfEvent, scName string) []handler.PayloadSection
type payloadSourceSectionRule func(event payloadEvent, scName string) []handler.PayloadSection

var payloadSourceSectionRules = map[string]payloadSourceSectionRule{
	"write":    writePayloadSectionsFromSource,
	"pwrite64": writePayloadSectionsFromSource,
	"read":     readPayloadSectionsFromSource,
	"pread64":  readPayloadSectionsFromSource,

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

	"execve":   execPayloadSectionsFromSource,
	"execveat": execPayloadSectionsFromSource,

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
	"setrlimit":  enterStructPayloadSourceRule(1, handler.BpfEnterArgOffset, rlimitPayloadStructSize),
	"prlimit64":  prlimitPayloadSectionsFromSource,
	"arch_prctl": exitStructPayloadSourceRule(1, archPrctlPayloadOutSize),

	"get_robust_list": robustListPayloadSectionsFromSource,
	"waitid":          waitidPayloadSectionsFromSource,

	"copy_file_range": copyFileRangePayloadSectionsFromSource,
	"clone3":          clone3PayloadSectionsFromSource,
	"cachestat":       cachestatPayloadSectionsFromSource,
	"capget":          capabilityPayloadSectionsFromSource,
	"capset":          capabilityPayloadSectionsFromSource,
	"fcntl":           fcntlPayloadSectionsFromSource,
	"fcntl64":         fcntlPayloadSectionsFromSource,
	"prctl":           prctlPayloadSectionsFromSource,
}

var payloadSectionRules = map[string]payloadSectionRule{
	"bpf":          namedPayloadRule(bpfPayloadSectionsForEvent),
	"mount":        fsPayloadSectionsForEvent,
	"umount2":      fsPayloadSectionsForEvent,
	"fsconfig":     fsPayloadSectionsForEvent,
	"add_key":      keyPayloadSectionsForEvent,
	"request_key":  keyPayloadSectionsForEvent,
	"setxattr":     xattrPayloadSectionsForEvent,
	"lsetxattr":    xattrPayloadSectionsForEvent,
	"fsetxattr":    xattrPayloadSectionsForEvent,
	"getxattr":     xattrPayloadSectionsForEvent,
	"lgetxattr":    xattrPayloadSectionsForEvent,
	"fgetxattr":    xattrPayloadSectionsForEvent,
	"removexattr":  xattrPayloadSectionsForEvent,
	"lremovexattr": xattrPayloadSectionsForEvent,
	"fremovexattr": xattrPayloadSectionsForEvent,
	"listxattr":    xattrPayloadSectionsForEvent,
	"llistxattr":   xattrPayloadSectionsForEvent,
	"flistxattr":   xattrPayloadSectionsForEvent,
	"ioctl":        namedPayloadRule(ioctlPayloadSectionsForEvent),

	"io_setup":             aioPayloadSectionsForEvent,
	"io_submit":            aioPayloadSectionsForEvent,
	"io_cancel":            aioPayloadSectionsForEvent,
	"io_getevents":         aioPayloadSectionsForEvent,
	"io_pgetevents":        aioPayloadSectionsForEvent,
	"io_pgetevents_time64": aioPayloadSectionsForEvent,
	"rt_sigaction":         signalPayloadSectionsForEvent,
	"rt_sigprocmask":       signalPayloadSectionsForEvent,
	"rt_sigsuspend":        signalPayloadSectionsForEvent,
	"clock_gettime":        timePayloadSectionsForEvent,
	"clock_getres":         timePayloadSectionsForEvent,
	"clock_settime":        timePayloadSectionsForEvent,
	"adjtimex":             timePayloadSectionsForEvent,
	"clock_adjtime":        timePayloadSectionsForEvent,
	"nanosleep":            timePayloadSectionsForEvent,
	"clock_nanosleep":      timePayloadSectionsForEvent,
	"gettimeofday":         timePayloadSectionsForEvent,
	"settimeofday":         timePayloadSectionsForEvent,
	"getitimer":            timePayloadSectionsForEvent,
	"setitimer":            timePayloadSectionsForEvent,
	"utime":                timePayloadSectionsForEvent,
	"utimes":               timePayloadSectionsForEvent,
	"futimesat":            timePayloadSectionsForEvent,
	"utimensat":            timePayloadSectionsForEvent,
	"futex":                futexPayloadSectionsForEvent,
	"futex_wait":           futexPayloadSectionsForEvent,
	"futex_waitv":          futexPayloadSectionsForEvent,
	"futex_requeue":        futexPayloadSectionsForEvent,
	"poll":                 pollPayloadRule(false),
	"ppoll":                pollPayloadRule(true),
	"select":               namedPayloadRule(selectPayloadSectionsForEvent),
	"_newselect":           namedPayloadRule(selectPayloadSectionsForEvent),
	"epoll_ctl":            enterStructPayloadRule(3, handler.BpfEnterArgOffset, epollPayloadEventSize),
	"epoll_wait":           exitStructArrayPayloadRule(1, epollPayloadEventSize, epollPayloadMaxBytes),
	"epoll_pwait":          exitStructArrayPayloadRule(1, epollPayloadEventSize, epollPayloadMaxBytes),
	"epoll_pwait2":         namedPayloadRule(epollPwait2PayloadSectionsForEvent),
	"connect":              networkSockaddrInPayloadRule(1, 2, 0),
	"bind":                 networkSockaddrInPayloadRule(1, 2, 0),
	"sendto":               namedPayloadRule(sendtoPayloadSectionsForEvent),
	"recvfrom":             namedPayloadRule(recvfromPayloadSectionsForEvent),
	"accept":               namedPayloadRule(acceptLikePayloadSectionsForEvent),
	"accept4":              namedPayloadRule(acceptLikePayloadSectionsForEvent),
	"getsockname":          namedPayloadRule(acceptLikePayloadSectionsForEvent),
	"getpeername":          namedPayloadRule(acceptLikePayloadSectionsForEvent),
}

func payloadSectionsForEvent(eventRaw *bpfEvent, scMeta meta.Syscall) []handler.PayloadSection {
	return payloadSectionsForPayloadEvent(newFixedPayloadEvent(eventRaw), scMeta)
}

func payloadSectionsForPayloadEvent(event payloadEvent, scMeta meta.Syscall) []handler.PayloadSection {
	if rule, ok := payloadSourceSectionRules[scMeta.Name]; ok {
		return rule(event, scMeta.Name)
	}
	if argIndex, ok := simplePathPayloadArgIndex(scMeta.Name); ok {
		return stringPayloadSectionFromSource(event, argIndex)
	}
	eventRaw := event.raw
	if eventRaw == nil {
		return nil
	}
	if rule, ok := payloadSectionRules[scMeta.Name]; ok {
		return rule(eventRaw, scMeta.Name)
	}
	return nil
}

func namedPayloadRule(fn func(*bpfEvent) []handler.PayloadSection) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return fn(eventRaw)
	}
}

func exitBytesPayloadRule(argIndex int) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return exitBytesPayloadSectionFromRet(eventRaw, argIndex)
	}
}

func exitBytesPayloadSourceRule(argIndex int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return exitBytesPayloadSectionFromSourceRet(event, argIndex)
	}
}

func exitStructPayloadRule(argIndex int, size uint32) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return exitStructPayloadSection(eventRaw, argIndex, size)
	}
}

func exitStructPayloadSourceRule(argIndex int, size uint32) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return exitStructPayloadSectionFromSource(event, argIndex, size)
	}
}

func enterStructPayloadRule(argIndex int, offset int, size uint32) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return enterStructPayloadSection(eventRaw, argIndex, offset, size)
	}
}

func enterStructPayloadSourceRule(argIndex int, offset int, size uint32) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return enterStructPayloadSectionFromSource(event, argIndex, offset, size)
	}
}

func exitStructArrayPayloadRule(argIndex int, elemSize int, maxBytes int) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return exitStructArrayPayloadSectionFromRet(eventRaw, argIndex, elemSize, maxBytes)
	}
}

func dualPathPayloadSourceRule(firstArg int, secondArg int) payloadSourceSectionRule {
	return func(event payloadEvent, _ string) []handler.PayloadSection {
		return dualPathPayloadSectionsFromSource(event, firstArg, secondArg)
	}
}

func pollPayloadRule(includeTimeout bool) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return pollPayloadSectionsForEvent(eventRaw, includeTimeout)
	}
}

func networkSockaddrInPayloadRule(argIndex int, lenIndex int, offset int) payloadSectionRule {
	return func(eventRaw *bpfEvent, _ string) []handler.PayloadSection {
		return networkSockaddrInPayloadSection(eventRaw, argIndex, lenIndex, offset)
	}
}

func writePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	userLen := uint32Clamped(event.Arg(2))
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  1,
		userLen:   userLen,
		maxLen:    userLen,
		probeRet:  event.ProbeRetEnterArg(1),
	})
}

func readPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() <= 0 {
		return nil
	}
	userLen := uint32Clamped(uint64(event.Ret()))
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  1,
		offset:    handler.BpfExitArgOffset,
		userLen:   userLen,
		maxLen:    userLen,
		probeRet:  event.ProbeRetExit(),
	})
}

func memfdCreatePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: 0,
		maxBytes: memfdNamePayloadMaxBytes,
	})
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

func iovecUserLen(count uint64) uint32 {
	if count > uint64(^uint32(0))/iovecSectionElemSize {
		return ^uint32(0)
	}
	return uint32(count * iovecSectionElemSize)
}

func payloadSectionFromWindowSpec(eventRaw *bpfEvent, spec payloadWindowSpec) []handler.PayloadSection {
	return payloadSectionFromSourceSpec(newFixedEventPayloadSource(eventRaw), spec)
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

func eventPayloadWindow(eventRaw *bpfEvent, offset int, maxLen int) ([]byte, bool) {
	return newFixedEventPayloadSource(eventRaw).PayloadWindow(offset, maxLen)
}

func newPayloadSection(eventRaw *bpfEvent, spec payloadWindowSpec, data []byte) handler.PayloadSection {
	return newPayloadSectionFromSource(newFixedEventPayloadSource(eventRaw), spec, data)
}

func newPayloadSectionFromSource(source payloadSource, spec payloadWindowSpec, data []byte) handler.PayloadSection {
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
	if userPtr, ok := source.Arg(spec.argIndex); ok {
		section.UserPtr = userPtr
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
