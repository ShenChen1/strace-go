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

func xattrPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "setxattr", "lsetxattr":
		return xattrSetPayloadSections(event, xattrNamePayloadOffset, xattrValuePayloadOffset, true)
	case "fsetxattr":
		return xattrSetPayloadSections(event, xattrFNamePayloadOffset, xattrFValuePayloadOffset, false)
	case "getxattr", "lgetxattr":
		return xattrGetPayloadSections(event, xattrNamePayloadOffset, xattrValuePayloadOffset, true)
	case "fgetxattr":
		return xattrGetPayloadSections(event, xattrFNamePayloadOffset, xattrFValuePayloadOffset, false)
	case "removexattr", "lremovexattr":
		sections := xattrPathPayloadSection(event)
		return append(sections, xattrNamePayloadSection(event, 1, xattrNamePayloadOffset)...)
	case "fremovexattr":
		return xattrNamePayloadSection(event, 1, xattrFNamePayloadOffset)
	case "listxattr", "llistxattr":
		sections := xattrPathPayloadSection(event)
		return append(sections, xattrListPayloadSection(event, xattrListPayloadOffset)...)
	case "flistxattr":
		return xattrListPayloadSection(event, xattrFListPayloadOffset)
	default:
		return nil
	}
}

func xattrSetPayloadSections(event payloadEvent, nameOffset int, valueOffset int, includePath bool) []handler.PayloadSection {
	var sections []handler.PayloadSection
	if includePath {
		sections = xattrPathPayloadSection(event)
	}
	sections = append(sections, xattrNamePayloadSection(event, 1, nameOffset)...)
	return append(sections, xattrValuePayloadSection(event, valueOffset, handler.PayloadDirectionIn)...)
}

func xattrGetPayloadSections(event payloadEvent, nameOffset int, valueOffset int, includePath bool) []handler.PayloadSection {
	var sections []handler.PayloadSection
	if includePath {
		sections = xattrPathPayloadSection(event)
	}
	sections = append(sections, xattrNamePayloadSection(event, 1, nameOffset)...)
	return append(sections, xattrValuePayloadSection(event, valueOffset, handler.PayloadDirectionOut)...)
}

func xattrPathPayloadSection(event payloadEvent) []handler.PayloadSection {
	return xattrStringPayloadSection(event, 0, xattrPathPayloadOffset, xattrPathPayloadMaxBytes)
}

func xattrNamePayloadSection(event payloadEvent, argIndex int, offset int) []handler.PayloadSection {
	return xattrStringPayloadSection(event, argIndex, offset, xattrNamePayloadMaxBytes)
}

func xattrStringPayloadSection(event payloadEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	if event.Arg(argIndex) == 0 {
		return nil
	}
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: argIndex,
		offset:   offset,
		maxBytes: maxLen,
	})
}

func xattrValuePayloadSection(event payloadEvent, offset int, direction handler.PayloadDirection) []handler.PayloadSection {
	if direction == handler.PayloadDirectionOut && (!event.IsExit() || event.Ret() <= 0) {
		return nil
	}
	if event.Arg(2) == 0 || event.Arg(3) == 0 {
		return nil
	}
	userLen := uint32Clamped(event.Arg(3))
	probeRet := event.ProbeRetEnterArg(2)
	if direction == handler.PayloadDirectionOut {
		userLen = uint32Clamped(uint64(event.Ret()))
		probeRet = event.ProbeRetExit()
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  2,
		offset:    offset,
		userLen:   userLen,
		maxLen:    xattrValuePayloadMaxBytes,
		probeRet:  probeRet,
	})
}

func xattrListPayloadSection(event payloadEvent, offset int) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() <= 0 || event.Arg(1) == 0 || event.Arg(2) == 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  1,
		offset:    offset,
		userLen:   uint32Clamped(uint64(event.Ret())),
		maxLen:    xattrListPayloadMaxBytes,
		probeRet:  event.ProbeRetExit(),
	})
}
