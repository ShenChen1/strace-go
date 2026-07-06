package main

import "strace-go/pkg/handler"

const (
	futexPayloadWaitvElemSize      = 24
	futexPayloadWaitvMaxBytes      = 3072
	futexPayloadWaitvTimeoutOffset = futexPayloadWaitvMaxBytes
	futexPayloadRequeueSize        = 48
)

func futexPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "futex":
		if !futexHasTimeout(event.Arg(1)) {
			return nil
		}
		return futexStructPayloadSection(event, 3, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, timespecPayloadStructSize)
	case "futex_wait":
		return futexStructPayloadSection(event, 4, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, timespecPayloadStructSize)
	case "futex_waitv":
		sections := futexWaitvPayloadSection(event)
		return append(sections, futexStructPayloadSection(event, 3, handler.PayloadDirectionIn, futexPayloadWaitvTimeoutOffset, timespecPayloadStructSize)...)
	case "futex_requeue":
		return futexStructPayloadSection(event, 0, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, futexPayloadRequeueSize)
	default:
		return nil
	}
}

func futexHasTimeout(op uint64) bool {
	baseOp := op & 0x7f
	return baseOp == 0 || baseOp == 11 || baseOp == 2
}

func futexWaitvPayloadSection(event payloadEvent) []handler.PayloadSection {
	if event.Arg(0) == 0 {
		return nil
	}
	probeRet := event.ProbeRetEnterArg(0)
	if probeRet != 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  0,
		offset:    handler.BpfEnterArgOffset,
		userLen:   structArrayUserLen(event.Arg(1), futexPayloadWaitvElemSize),
		maxLen:    futexPayloadWaitvMaxBytes,
		probeRet:  probeRet,
	})
}

func futexStructPayloadSection(
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
		probeRet:  futexPayloadProbeRet(event, argIndex, direction),
	})
}

func futexPayloadProbeRet(
	event payloadEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return event.ProbeRetExit()
	}
	return event.ProbeRetEnterArg(argIndex)
}
