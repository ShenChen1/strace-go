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

func selectPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := make([]handler.PayloadSection, 0, 8)
	for argIndex := selectPayloadFdSetArgBase; argIndex <= selectPayloadFdSetArgLast; argIndex++ {
		sections = append(sections, selectFdSetPayloadSection(
			event,
			argIndex,
			handler.PayloadDirectionIn,
			selectPayloadFdSetOffset(argIndex),
		)...)
	}
	sections = append(sections, selectTimeoutPayloadSection(
		event,
		handler.PayloadDirectionIn,
		selectPayloadTimeoutOffset,
	)...)

	if event.IsExit() && event.Ret() > 0 {
		for argIndex := selectPayloadFdSetArgBase; argIndex <= selectPayloadFdSetArgLast; argIndex++ {
			sections = append(sections, selectFdSetPayloadSection(
				event,
				argIndex,
				handler.PayloadDirectionOut,
				selectPayloadExitFdSetOffset+selectPayloadFdSetOffset(argIndex),
			)...)
		}
	}
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, selectTimeoutPayloadSection(
			event,
			handler.PayloadDirectionOut,
			selectPayloadExitTimeoutOff,
		)...)
	}
	return sections
}

func selectFdSetPayloadSection(
	event payloadEvent,
	argIndex int,
	direction handler.PayloadDirection,
	offset int,
) []handler.PayloadSection {
	if event.Arg(argIndex) == 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   selectFdSetUserLen(event.Arg(0)),
		maxLen:    selectPayloadFdSetSize,
		probeRet:  selectPayloadProbeRet(event, argIndex, direction),
	})
}

func selectTimeoutPayloadSection(
	event payloadEvent,
	direction handler.PayloadDirection,
	offset int,
) []handler.PayloadSection {
	if event.Arg(selectPayloadTimeoutArg) == 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: direction,
		argIndex:  selectPayloadTimeoutArg,
		offset:    offset,
		userLen:   selectPayloadTimeoutSize,
		maxLen:    selectPayloadTimeoutSize,
		probeRet:  selectPayloadProbeRet(event, selectPayloadTimeoutArg, direction),
	})
}

func selectPayloadProbeRet(
	event payloadEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return event.ProbeRetExit()
	}
	return event.ProbeRetEnterArg(argIndex)
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
