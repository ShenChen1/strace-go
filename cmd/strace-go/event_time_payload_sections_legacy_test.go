package main

import "strace-go/pkg/handler"

const (
	timePayloadStructOffset   = payloadEnterArgOffset
	timePayloadExitOffset     = payloadExitArgOffset
	timePayloadPathOffset     = payloadEnterArgOffset
	timePayloadValueOffset    = payloadMiscArgOffset
	timePayloadTimezoneSize   = 8
	timePayloadTimezoneOffset = payloadExitArgOffset + timespecPayloadStructSize
	timePayloadTimexSize      = 208
	timePayloadItimervalSize  = 32
	timePayloadUtimbufSize    = 16
)

func timePayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "clock_gettime", "clock_getres":
		return successfulTimeOutSection(event, 1, timePayloadExitOffset, timespecPayloadStructSize)
	case "clock_settime":
		return timeStructPayloadSection(event, 1, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	case "adjtimex":
		return timexPayloadSections(event, 0)
	case "clock_adjtime":
		return timexPayloadSections(event, 1)
	case "nanosleep":
		return nanosleepPayloadSections(event, 0, 1)
	case "clock_nanosleep":
		return nanosleepPayloadSections(event, 2, 3)
	case "gettimeofday":
		return gettimeofdayPayloadSections(event)
	case "settimeofday":
		return settimeofdayPayloadSections(event)
	case "getitimer":
		return successfulTimeOutSection(event, 1, timePayloadExitOffset, timePayloadItimervalSize)
	case "setitimer":
		return setitimerPayloadSections(event)
	case "utime":
		return fileTimePayloadSections(event, 0, 1, timePayloadUtimbufSize)
	case "utimes":
		return fileTimePayloadSections(event, 0, 1, timePayloadItimervalSize)
	case "futimesat", "utimensat":
		return fileTimePayloadSections(event, 1, 2, timePayloadItimervalSize)
	default:
		return nil
	}
}

func fileTimePayloadSections(event payloadEvent, pathArg int, timeArg int, timeSize uint32) []handler.PayloadSection {
	sections := stringPayloadSectionFromSourceAt(event, pathPayloadSpec{
		argIndex: pathArg,
		offset:   timePayloadPathOffset,
	})
	return append(sections, timeStructPayloadSection(event, timeArg, handler.PayloadDirectionIn, timePayloadValueOffset, timeSize)...)
}

func timexPayloadSections(event payloadEvent, argIndex int) []handler.PayloadSection {
	sections := timeStructPayloadSection(event, argIndex, handler.PayloadDirectionIn, timePayloadStructOffset, timePayloadTimexSize)
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, timeStructPayloadSection(event, argIndex, handler.PayloadDirectionOut, timePayloadExitOffset, timePayloadTimexSize)...)
	}
	return sections
}

func nanosleepPayloadSections(event payloadEvent, inArg int, outArg int) []handler.PayloadSection {
	sections := timeStructPayloadSection(event, inArg, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	if event.IsExit() && isInterruptedSleepRet(event.Ret()) {
		sections = append(sections, timeStructPayloadSection(event, outArg, handler.PayloadDirectionOut, timePayloadExitOffset, timespecPayloadStructSize)...)
	}
	return sections
}

func gettimeofdayPayloadSections(event payloadEvent) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	sections := timeStructPayloadSection(event, 0, handler.PayloadDirectionOut, timePayloadExitOffset, timespecPayloadStructSize)
	return append(sections, timeStructPayloadSection(event, 1, handler.PayloadDirectionOut, timePayloadTimezoneOffset, timePayloadTimezoneSize)...)
}

func settimeofdayPayloadSections(event payloadEvent) []handler.PayloadSection {
	sections := timeStructPayloadSection(event, 0, handler.PayloadDirectionIn, timePayloadStructOffset, timespecPayloadStructSize)
	return append(sections, timeStructPayloadSection(event, 1, handler.PayloadDirectionIn, timespecPayloadStructSize, timePayloadTimezoneSize)...)
}

func setitimerPayloadSections(event payloadEvent) []handler.PayloadSection {
	sections := timeStructPayloadSection(event, 1, handler.PayloadDirectionIn, timePayloadStructOffset, timePayloadItimervalSize)
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, timeStructPayloadSection(event, 2, handler.PayloadDirectionOut, timePayloadExitOffset, timePayloadItimervalSize)...)
	}
	return sections
}

func successfulTimeOutSection(event payloadEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	return timeStructPayloadSection(event, argIndex, handler.PayloadDirectionOut, offset, size)
}

func timeStructPayloadSection(
	event payloadEvent,
	argIndex int,
	direction handler.PayloadDirection,
	offset int,
	size uint32,
) []handler.PayloadSection {
	if argIndex < 0 || argIndex >= 6 || event.Arg(argIndex) == 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  timePayloadProbeRet(event, argIndex, direction),
	})
}

func timePayloadProbeRet(
	event payloadEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return event.ProbeRetExit()
	}
	return event.ProbeRetEnterArg(argIndex)
}

func isInterruptedSleepRet(ret int64) bool {
	return ret == -516 || ret == -4
}
