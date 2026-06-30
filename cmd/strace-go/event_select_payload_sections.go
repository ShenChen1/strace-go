package main

import "strace-go/pkg/handler"

const (
	selectPayloadFdSetSize       = 128
	selectPayloadFdSetArgBase    = 1
	selectPayloadFdSetArgLast    = 3
	selectPayloadFdSetArgSpacing = 128
	selectPayloadTimeoutArg      = 4
	selectPayloadTimeoutSize     = 16
	selectPayloadTimeoutOffset   = 384
	selectPayloadExitFdSetOffset = handler.BpfExitArgOffset
	selectPayloadExitTimeoutOff  = 1408
)

func selectPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := make([]handler.PayloadSection, 0, 8)
	for argIndex := selectPayloadFdSetArgBase; argIndex <= selectPayloadFdSetArgLast; argIndex++ {
		sections = append(sections, selectFdSetPayloadSection(
			eventRaw,
			argIndex,
			handler.PayloadDirectionIn,
			selectPayloadFdSetOffset(argIndex),
		)...)
	}
	sections = append(sections, selectTimeoutPayloadSection(
		eventRaw,
		handler.PayloadDirectionIn,
		selectPayloadTimeoutOffset,
	)...)

	if isExitEvent(eventRaw) && eventRaw.Ret > 0 {
		for argIndex := selectPayloadFdSetArgBase; argIndex <= selectPayloadFdSetArgLast; argIndex++ {
			sections = append(sections, selectFdSetPayloadSection(
				eventRaw,
				argIndex,
				handler.PayloadDirectionOut,
				selectPayloadExitFdSetOffset+selectPayloadFdSetOffset(argIndex),
			)...)
		}
	}
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, selectTimeoutPayloadSection(
			eventRaw,
			handler.PayloadDirectionOut,
			selectPayloadExitTimeoutOff,
		)...)
	}
	return sections
}

func selectFdSetPayloadSection(
	eventRaw *bpfEvent,
	argIndex int,
	direction handler.PayloadDirection,
	offset int,
) []handler.PayloadSection {
	if eventRaw.Args[argIndex] == 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   selectFdSetUserLen(eventRaw.Args[0]),
		maxLen:    selectPayloadFdSetSize,
		probeRet:  selectPayloadProbeRet(eventRaw, argIndex, direction),
	})
}

func selectTimeoutPayloadSection(
	eventRaw *bpfEvent,
	direction handler.PayloadDirection,
	offset int,
) []handler.PayloadSection {
	if eventRaw.Args[selectPayloadTimeoutArg] == 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: direction,
		argIndex:  selectPayloadTimeoutArg,
		offset:    offset,
		userLen:   selectPayloadTimeoutSize,
		maxLen:    selectPayloadTimeoutSize,
		probeRet:  selectPayloadProbeRet(eventRaw, selectPayloadTimeoutArg, direction),
	})
}

func selectPayloadProbeRet(
	eventRaw *bpfEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return eventRaw.ProbeRetExit
	}
	return getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex)
}

func selectFdSetUserLen(nfds uint64) uint32 {
	if nfds == 0 {
		return 0
	}
	if nfds > uint64(selectPayloadFdSetSize*8) {
		return selectPayloadFdSetSize
	}
	userLen := (nfds + 7) / 8
	return uint32(userLen)
}

func selectPayloadFdSetOffset(argIndex int) int {
	return (argIndex - selectPayloadFdSetArgBase) * selectPayloadFdSetArgSpacing
}
