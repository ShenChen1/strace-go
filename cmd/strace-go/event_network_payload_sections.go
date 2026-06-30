package main

import (
	"encoding/binary"

	"strace-go/pkg/handler"
)

const (
	networkPayloadMaxBytes   = 512
	sockaddrPayloadMaxBytes  = 128
	socklenPayloadSize       = 4
	sockaddrLenEnterOffset   = 768
	sockaddrLenExitOffset    = 772
	recvfromSockaddrOffset   = 1536
	sendtoSockaddrOffset     = handler.BpfMiscArgOffset
	acceptSockaddrOutOffset  = handler.BpfExitArgOffset
	networkBufferEnterOffset = handler.BpfEnterArgOffset
	networkBufferExitOffset  = handler.BpfExitArgOffset
)

func sendtoPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := networkBytesPayloadSectionFromArg(eventRaw, handler.PayloadDirectionIn, 1, 2, networkBufferEnterOffset)
	sections = append(sections, networkSockaddrInPayloadSection(eventRaw, 4, 5, sendtoSockaddrOffset)...)
	return sections
}

func recvfromPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := socklenPayloadSection(eventRaw, handler.PayloadDirectionIn, 5, sockaddrLenEnterOffset, getArgProbeStatus(eventRaw.ProbeRetEnter, 5))
	if !isExitEvent(eventRaw) {
		return sections
	}
	sections = append(sections, networkBytesPayloadSectionFromRet(eventRaw, 1, networkBufferExitOffset)...)
	sections = append(sections, networkSockaddrOutPayloadSection(eventRaw, 4, recvfromSockaddrOffset)...)
	sections = append(sections, socklenPayloadSection(eventRaw, handler.PayloadDirectionOut, 5, sockaddrLenExitOffset, eventRaw.ProbeRetExit)...)
	return sections
}

func acceptLikePayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := socklenPayloadSection(eventRaw, handler.PayloadDirectionIn, 2, sockaddrLenEnterOffset, getArgProbeStatus(eventRaw.ProbeRetEnter, 2))
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return sections
	}
	sections = append(sections, networkSockaddrOutPayloadSection(eventRaw, 1, acceptSockaddrOutOffset)...)
	sections = append(sections, socklenPayloadSection(eventRaw, handler.PayloadDirectionOut, 2, sockaddrLenExitOffset, eventRaw.ProbeRetExit)...)
	return sections
}

func networkBytesPayloadSectionFromArg(eventRaw *bpfEvent, direction handler.PayloadDirection, argIndex int, lenIndex int, offset int) []handler.PayloadSection {
	if lenIndex < 0 || lenIndex >= len(eventRaw.Args) {
		return nil
	}
	userLen := uint32Clamped(eventRaw.Args[lenIndex])
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		maxLen:    networkPayloadMaxBytes,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	})
}

func networkBytesPayloadSectionFromRet(eventRaw *bpfEvent, argIndex int, offset int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   uint32Clamped(uint64(eventRaw.Ret)),
		maxLen:    networkPayloadMaxBytes,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func networkSockaddrInPayloadSection(eventRaw *bpfEvent, argIndex int, lenIndex int, offset int) []handler.PayloadSection {
	if lenIndex < 0 || lenIndex >= len(eventRaw.Args) {
		return nil
	}
	userLen := uint32Clamped(eventRaw.Args[lenIndex])
	return sockaddrPayloadSection(eventRaw, payloadWindowSpec{
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	})
}

func networkSockaddrOutPayloadSection(eventRaw *bpfEvent, argIndex int, offset int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	userLen := networkSockaddrOutLen(eventRaw)
	if userLen == 0 {
		userLen = sockaddrPayloadMaxBytes
	}
	return sockaddrPayloadSection(eventRaw, payloadWindowSpec{
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func sockaddrPayloadSection(eventRaw *bpfEvent, spec payloadWindowSpec) []handler.PayloadSection {
	spec.kind = handler.PayloadKindStruct
	spec.maxLen = sockaddrPayloadMaxBytes
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      spec.kind,
		direction: spec.direction,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   spec.userLen,
		maxLen:    spec.maxLen,
		probeRet:  spec.probeRet,
	})
}

func socklenPayloadSection(eventRaw *bpfEvent, direction handler.PayloadDirection, argIndex int, offset int, probeRet int32) []handler.PayloadSection {
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   socklenPayloadSize,
		maxLen:    socklenPayloadSize,
		probeRet:  probeRet,
	})
}

func networkSockaddrOutLen(eventRaw *bpfEvent) uint32 {
	outLen, outOK := socklenFromEventPayload(eventRaw, sockaddrLenExitOffset)
	inLen, inOK := socklenFromEventPayload(eventRaw, sockaddrLenEnterOffset)
	if outOK && inOK && inLen > 0 && inLen < outLen {
		return inLen
	}
	if outOK {
		return outLen
	}
	if inOK {
		return inLen
	}
	return 0
}

func socklenFromEventPayload(eventRaw *bpfEvent, offset int) (uint32, bool) {
	data, ok := eventPayloadWindow(eventRaw, offset, socklenPayloadSize)
	if !ok || len(data) < socklenPayloadSize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}
