package main

import "strace-go/pkg/handler"

const (
	xattrPathPayloadOffset    = 0
	xattrPathPayloadMaxBytes  = 512
	xattrNamePayloadOffset    = 512
	xattrNamePayloadMaxBytes  = 256
	xattrFNamePayloadOffset   = 0
	xattrValuePayloadOffset   = 768
	xattrFValuePayloadOffset  = 256
	xattrValuePayloadMaxBytes = 256
	xattrListPayloadOffset    = 512
	xattrFListPayloadOffset   = 0
	xattrListPayloadMaxBytes  = 256
)

func xattrPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "setxattr", "lsetxattr":
		return xattrSetPayloadSections(eventRaw, xattrNamePayloadOffset, xattrValuePayloadOffset, true)
	case "fsetxattr":
		return xattrSetPayloadSections(eventRaw, xattrFNamePayloadOffset, xattrFValuePayloadOffset, false)
	case "getxattr", "lgetxattr":
		return xattrGetPayloadSections(eventRaw, xattrNamePayloadOffset, xattrValuePayloadOffset, true)
	case "fgetxattr":
		return xattrGetPayloadSections(eventRaw, xattrFNamePayloadOffset, xattrFValuePayloadOffset, false)
	case "removexattr", "lremovexattr":
		sections := xattrPathPayloadSection(eventRaw)
		return append(sections, xattrNamePayloadSection(eventRaw, 1, xattrNamePayloadOffset)...)
	case "fremovexattr":
		return xattrNamePayloadSection(eventRaw, 1, xattrFNamePayloadOffset)
	case "listxattr", "llistxattr":
		sections := xattrPathPayloadSection(eventRaw)
		return append(sections, xattrListPayloadSection(eventRaw, xattrListPayloadOffset)...)
	case "flistxattr":
		return xattrListPayloadSection(eventRaw, xattrFListPayloadOffset)
	default:
		return nil
	}
}

func xattrSetPayloadSections(eventRaw *bpfEvent, nameOffset int, valueOffset int, includePath bool) []handler.PayloadSection {
	var sections []handler.PayloadSection
	if includePath {
		sections = xattrPathPayloadSection(eventRaw)
	}
	sections = append(sections, xattrNamePayloadSection(eventRaw, 1, nameOffset)...)
	return append(sections, xattrValuePayloadSection(eventRaw, valueOffset, handler.PayloadDirectionIn)...)
}

func xattrGetPayloadSections(eventRaw *bpfEvent, nameOffset int, valueOffset int, includePath bool) []handler.PayloadSection {
	var sections []handler.PayloadSection
	if includePath {
		sections = xattrPathPayloadSection(eventRaw)
	}
	sections = append(sections, xattrNamePayloadSection(eventRaw, 1, nameOffset)...)
	return append(sections, xattrValuePayloadSection(eventRaw, valueOffset, handler.PayloadDirectionOut)...)
}

func xattrPathPayloadSection(eventRaw *bpfEvent) []handler.PayloadSection {
	return xattrStringPayloadSection(eventRaw, 0, xattrPathPayloadOffset, xattrPathPayloadMaxBytes)
}

func xattrNamePayloadSection(eventRaw *bpfEvent, argIndex int, offset int) []handler.PayloadSection {
	return xattrStringPayloadSection(eventRaw, argIndex, offset, xattrNamePayloadMaxBytes)
}

func xattrStringPayloadSection(eventRaw *bpfEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	if eventRaw.Args[argIndex] == 0 {
		return nil
	}
	return fsStringPayloadSection(eventRaw, argIndex, offset, maxLen)
}

func xattrValuePayloadSection(eventRaw *bpfEvent, offset int, direction handler.PayloadDirection) []handler.PayloadSection {
	if direction == handler.PayloadDirectionOut && (!isExitEvent(eventRaw) || eventRaw.Ret <= 0) {
		return nil
	}
	if eventRaw.Args[2] == 0 || eventRaw.Args[3] == 0 {
		return nil
	}
	userLen := uint32Clamped(eventRaw.Args[3])
	probeRet := getArgProbeStatus(eventRaw.ProbeRetEnter, 2)
	if direction == handler.PayloadDirectionOut {
		userLen = uint32Clamped(uint64(eventRaw.Ret))
		probeRet = eventRaw.ProbeRetExit
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  2,
		offset:    offset,
		userLen:   userLen,
		maxLen:    xattrValuePayloadMaxBytes,
		probeRet:  probeRet,
	})
}

func xattrListPayloadSection(eventRaw *bpfEvent, offset int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 || eventRaw.Args[1] == 0 || eventRaw.Args[2] == 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  1,
		offset:    offset,
		userLen:   uint32Clamped(uint64(eventRaw.Ret)),
		maxLen:    xattrListPayloadMaxBytes,
		probeRet:  eventRaw.ProbeRetExit,
	})
}
