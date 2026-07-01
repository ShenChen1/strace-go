package main

import "strace-go/pkg/handler"

const (
	ioctlArgPayloadOffset   = handler.BpfMiscArgOffset
	ioctlArgPayloadMaxBytes = 512
	ioctlArgZeroPayloadLen  = 128
	ioctlArgSizeShift       = 16
	ioctlArgSizeMask        = 0x3fff
)

func ioctlPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	if eventRaw.Args[2] == 0 {
		return nil
	}
	sections := ioctlArgPayloadSection(eventRaw, handler.PayloadDirectionIn, ioctlArgPayloadOffset, getArgProbeStatus(eventRaw.ProbeRetEnter, 2))
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, ioctlArgPayloadSection(eventRaw, handler.PayloadDirectionOut, handler.BpfExitArgOffset, eventRaw.ProbeRetExit)...)
	}
	return sections
}

func ioctlArgPayloadSection(
	eventRaw *bpfEvent,
	direction handler.PayloadDirection,
	offset int,
	probeRet int32,
) []handler.PayloadSection {
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  2,
		offset:    offset,
		userLen:   ioctlArgUserLen(eventRaw.Args[1]),
		maxLen:    ioctlArgPayloadMaxBytes,
		probeRet:  probeRet,
	})
}

func ioctlArgUserLen(cmd uint64) uint32 {
	size := uint32((cmd >> ioctlArgSizeShift) & ioctlArgSizeMask)
	if size == 0 {
		return ioctlArgZeroPayloadLen
	}
	return size
}
