package main

import "strace-go/pkg/handler"

const (
	ioctlArgPayloadOffset   = handler.BpfMiscArgOffset
	ioctlArgPayloadMaxBytes = 512
	ioctlArgZeroPayloadLen  = 128
	ioctlArgSizeShift       = 16
	ioctlArgSizeMask        = 0x3fff
)

func ioctlPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	if event.Arg(2) == 0 {
		return nil
	}
	sections := ioctlArgPayloadSection(event, handler.PayloadDirectionIn, ioctlArgPayloadOffset, event.ProbeRetEnterArg(2))
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, ioctlArgPayloadSection(event, handler.PayloadDirectionOut, handler.BpfExitArgOffset, event.ProbeRetExit())...)
	}
	return sections
}

func ioctlArgPayloadSection(
	event payloadEvent,
	direction handler.PayloadDirection,
	offset int,
	probeRet int32,
) []handler.PayloadSection {
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  2,
		offset:    offset,
		userLen:   ioctlArgUserLen(event.Arg(1)),
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
