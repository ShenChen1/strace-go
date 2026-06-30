package main

import "strace-go/pkg/handler"

const (
	timePayloadStructOffset   = handler.BpfEnterArgOffset
	timePayloadExitOffset     = handler.BpfExitArgOffset
	timePayloadTimezoneSize   = 8
	timePayloadTimezoneOffset = handler.BpfExitArgOffset + timespecPayloadStructSize
	timePayloadTimexSize      = 208
	timePayloadItimervalSize  = 32
)

func timePayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "clock_gettime", "clock_getres":
		return successfulTimeOutSection(eventRaw, 1, timePayloadExitOffset, timespecPayloadStructSize)
	case "clock_settime":
		return timeStructPayloadSection(eventRaw, 1, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	case "adjtimex":
		return timexPayloadSections(eventRaw, 0)
	case "clock_adjtime":
		return timexPayloadSections(eventRaw, 1)
	case "nanosleep":
		return nanosleepPayloadSections(eventRaw, 0, 1)
	case "clock_nanosleep":
		return nanosleepPayloadSections(eventRaw, 2, 3)
	case "gettimeofday":
		return gettimeofdayPayloadSections(eventRaw)
	case "settimeofday":
		return settimeofdayPayloadSections(eventRaw)
	case "getitimer":
		return successfulTimeOutSection(eventRaw, 1, timePayloadExitOffset, timePayloadItimervalSize)
	case "setitimer":
		return setitimerPayloadSections(eventRaw)
	default:
		return nil
	}
}

func timexPayloadSections(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	sections := timeStructPayloadSection(eventRaw, argIndex, handler.PayloadDirectionIn, timePayloadStructOffset, timePayloadTimexSize)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, timeStructPayloadSection(eventRaw, argIndex, handler.PayloadDirectionOut, timePayloadExitOffset, timePayloadTimexSize)...)
	}
	return sections
}

func nanosleepPayloadSections(eventRaw *bpfEvent, inArg int, outArg int) []handler.PayloadSection {
	sections := timeStructPayloadSection(eventRaw, inArg, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	if isExitEvent(eventRaw) && isInterruptedSleepRet(eventRaw.Ret) {
		sections = append(sections, timeStructPayloadSection(eventRaw, outArg, handler.PayloadDirectionOut, timePayloadExitOffset, timespecPayloadStructSize)...)
	}
	return sections
}

func gettimeofdayPayloadSections(eventRaw *bpfEvent) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	sections := timeStructPayloadSection(eventRaw, 0, handler.PayloadDirectionOut, timePayloadExitOffset, timespecPayloadStructSize)
	return append(sections, timeStructPayloadSection(eventRaw, 1, handler.PayloadDirectionOut, timePayloadTimezoneOffset, timePayloadTimezoneSize)...)
}

func settimeofdayPayloadSections(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := timeStructPayloadSection(eventRaw, 0, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	return append(sections, timeStructPayloadSection(eventRaw, 1, handler.PayloadDirectionIn, timespecPayloadStructSize, timePayloadTimezoneSize)...)
}

func setitimerPayloadSections(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := timeStructPayloadSection(eventRaw, 1, handler.PayloadDirectionIn, timePayloadStructOffset, timePayloadItimervalSize)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, timeStructPayloadSection(eventRaw, 2, handler.PayloadDirectionOut, timePayloadExitOffset, timePayloadItimervalSize)...)
	}
	return sections
}

func successfulTimeOutSection(eventRaw *bpfEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	return timeStructPayloadSection(eventRaw, argIndex, handler.PayloadDirectionOut, offset, size)
}

func timeStructPayloadSection(
	eventRaw *bpfEvent,
	argIndex int,
	direction handler.PayloadDirection,
	offset int,
	size uint32,
) []handler.PayloadSection {
	if argIndex < 0 || argIndex >= len(eventRaw.Args) || eventRaw.Args[argIndex] == 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  timePayloadProbeRet(eventRaw, argIndex, direction),
	})
}

func timePayloadProbeRet(
	eventRaw *bpfEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return getArgProbeStatus(eventRaw.ProbeRetExit, argIndex)
	}
	return getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex)
}

func isInterruptedSleepRet(ret int64) bool {
	return ret == -516 || ret == -4
}
