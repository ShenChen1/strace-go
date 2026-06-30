package main

import "strace-go/pkg/handler"

const (
	futexPayloadWaitvElemSize      = 24
	futexPayloadWaitvMaxBytes      = 3072
	futexPayloadWaitvTimeoutOffset = futexPayloadWaitvMaxBytes
	futexPayloadRequeueSize        = 48
)

func futexPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "futex":
		if !futexHasTimeout(eventRaw.Args[1]) {
			return nil
		}
		return futexStructPayloadSection(eventRaw, 3, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, timespecPayloadStructSize)
	case "futex_wait":
		return futexStructPayloadSection(eventRaw, 4, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, timespecPayloadStructSize)
	case "futex_waitv":
		sections := futexWaitvPayloadSection(eventRaw)
		return append(sections, futexStructPayloadSection(eventRaw, 3, handler.PayloadDirectionIn, futexPayloadWaitvTimeoutOffset, timespecPayloadStructSize)...)
	case "futex_requeue":
		return futexStructPayloadSection(eventRaw, 0, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, futexPayloadRequeueSize)
	default:
		return nil
	}
}

func futexHasTimeout(op uint64) bool {
	baseOp := op & 0x7f
	return baseOp == 0 || baseOp == 11 || baseOp == 2
}

func futexWaitvPayloadSection(eventRaw *bpfEvent) []handler.PayloadSection {
	if eventRaw.Args[0] == 0 {
		return nil
	}
	probeRet := getArgProbeStatus(eventRaw.ProbeRetEnter, 0)
	if probeRet != 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  0,
		offset:    handler.BpfEnterArgOffset,
		userLen:   structArrayUserLen(eventRaw.Args[1], futexPayloadWaitvElemSize),
		maxLen:    futexPayloadWaitvMaxBytes,
		probeRet:  probeRet,
	})
}

func futexStructPayloadSection(
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
		probeRet:  futexPayloadProbeRet(eventRaw, argIndex, direction),
	})
}

func futexPayloadProbeRet(
	eventRaw *bpfEvent,
	argIndex int,
	direction handler.PayloadDirection,
) int32 {
	if direction == handler.PayloadDirectionOut {
		return getArgProbeStatus(eventRaw.ProbeRetExit, argIndex)
	}
	return getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex)
}
