package main

import (
	"bytes"
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
	switch scMeta.Name {
	case "write", "pwrite64":
		userLen := uint32Clamped(eventRaw.Args[2])
		return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
			kind:      handler.PayloadKindBytes,
			direction: handler.PayloadDirectionIn,
			argIndex:  1,
			userLen:   userLen,
			maxLen:    userLen,
			probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 1),
		})
	case "read", "pread64":
		if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
			return nil
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
		})
	case "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "vmsplice":
		return iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset)
	case "process_vm_readv", "process_vm_writev":
		sections := iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset)
		return append(sections, iovecPayloadSectionFromWindow(eventRaw, 3, 4, handler.BpfMiscArgOffset)...)
	case "getcwd":
		return exitBytesPayloadSectionFromRet(eventRaw, 0)
	case "readlink":
		return exitBytesPayloadSectionFromRet(eventRaw, 1)
	case "readlinkat":
		return exitBytesPayloadSectionFromRet(eventRaw, 2)
	case "open", "creat":
		return stringPayloadSectionFromWindow(eventRaw, 0)
	case "openat", "openat2":
		return stringPayloadSectionFromWindow(eventRaw, 1)
	case "stat", "lstat":
		return exitStructPayloadSection(eventRaw, 1, statPayloadStructSize)
	case "fstat":
		return exitStructPayloadSection(eventRaw, 1, statPayloadStructSize)
	case "newfstatat":
		return exitStructPayloadSection(eventRaw, 2, statPayloadStructSize)
	case "statfs":
		return exitStructPayloadSection(eventRaw, 1, statfsPayloadStructSize)
	case "fstatfs":
		return exitStructPayloadSection(eventRaw, 1, statfsPayloadStructSize)
	case "clock_gettime", "clock_getres", "clock_settime", "adjtimex", "clock_adjtime",
		"nanosleep", "clock_nanosleep", "gettimeofday", "settimeofday":
		return timePayloadSectionsForEvent(eventRaw, scMeta.Name)
	case "poll":
		return pollPayloadSectionsForEvent(eventRaw, false)
	case "ppoll":
		return pollPayloadSectionsForEvent(eventRaw, true)
	case "select", "_newselect":
		return selectPayloadSectionsForEvent(eventRaw)
	case "epoll_ctl":
		return enterStructPayloadSection(eventRaw, 3, handler.BpfEnterArgOffset, epollPayloadEventSize)
	case "epoll_wait", "epoll_pwait":
		return exitStructArrayPayloadSectionFromRet(eventRaw, 1, epollPayloadEventSize, epollPayloadMaxBytes)
	case "epoll_pwait2":
		return epollPwait2PayloadSectionsForEvent(eventRaw)
	case "connect", "bind":
		return networkSockaddrInPayloadSection(eventRaw, 1, 2, 0)
	case "sendto":
		return sendtoPayloadSectionsForEvent(eventRaw)
	case "recvfrom":
		return recvfromPayloadSectionsForEvent(eventRaw)
	case "accept", "accept4", "getsockname", "getpeername":
		return acceptLikePayloadSectionsForEvent(eventRaw)
	default:
		return nil
	}
}

func stringPayloadSectionFromWindow(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, 0, 4097)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		userLen:   uint32(len(data)),
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	}, data)
	return []handler.PayloadSection{section}
}

func exitBytesPayloadSectionFromRet(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
		return nil
	}
	userLen := uint32Clamped(uint64(eventRaw.Ret))
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   userLen,
		maxLen:    userLen,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func exitStructPayloadSection(eventRaw *bpfEvent, argIndex int, size uint32) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   size,
		maxLen:    size,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func enterStructPayloadSection(eventRaw *bpfEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
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
