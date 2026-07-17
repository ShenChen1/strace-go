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
	sendtoSockaddrOffset     = payloadMiscArgOffset
	acceptSockaddrOutOffset  = payloadExitArgOffset
	networkBufferEnterOffset = payloadEnterArgOffset
	networkBufferExitOffset  = payloadExitArgOffset
)

func sendtoPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := networkBytesPayloadSectionFromArg(event, handler.PayloadDirectionIn, 1, 2, networkBufferEnterOffset)
	sections = append(sections, networkSockaddrInPayloadSection(event, 4, 5, sendtoSockaddrOffset)...)
	return sections
}

func recvfromPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := socklenPayloadSection(event, handler.PayloadDirectionIn, 5, sockaddrLenEnterOffset, event.ProbeRetEnterArg(5))
	if !event.IsExit() {
		return sections
	}
	sections = append(sections, networkBytesPayloadSectionFromRet(event, 1, networkBufferExitOffset)...)
	sections = append(sections, networkSockaddrOutPayloadSection(event, 4, recvfromSockaddrOffset)...)
	sections = append(sections, socklenPayloadSection(event, handler.PayloadDirectionOut, 5, sockaddrLenExitOffset, event.ProbeRetExit())...)
	return sections
}

func acceptLikePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := socklenPayloadSection(event, handler.PayloadDirectionIn, 2, sockaddrLenEnterOffset, event.ProbeRetEnterArg(2))
	if !event.IsExit() || event.Ret() < 0 {
		return sections
	}
	sections = append(sections, networkSockaddrOutPayloadSection(event, 1, acceptSockaddrOutOffset)...)
	sections = append(sections, socklenPayloadSection(event, handler.PayloadDirectionOut, 2, sockaddrLenExitOffset, event.ProbeRetExit())...)
	return sections
}

func networkBytesPayloadSectionFromArg(event payloadEvent, direction handler.PayloadDirection, argIndex int, lenIndex int, offset int) []handler.PayloadSection {
	if lenIndex < 0 || lenIndex >= 6 {
		return nil
	}
	userLen := uint32Clamped(event.Arg(lenIndex))
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		maxLen:    networkPayloadMaxBytes,
		probeRet:  event.ProbeRetEnterArg(argIndex),
	})
}

func networkBytesPayloadSectionFromRet(event payloadEvent, argIndex int, offset int) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() <= 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   uint32Clamped(uint64(event.Ret())),
		maxLen:    networkPayloadMaxBytes,
		probeRet:  event.ProbeRetExit(),
	})
}

func networkSockaddrInPayloadSection(event payloadEvent, argIndex int, lenIndex int, offset int) []handler.PayloadSection {
	if lenIndex < 0 || lenIndex >= 6 {
		return nil
	}
	userLen := uint32Clamped(event.Arg(lenIndex))
	return sockaddrPayloadSection(event, payloadWindowSpec{
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		probeRet:  event.ProbeRetEnterArg(argIndex),
	})
}

func networkSockaddrOutPayloadSection(event payloadEvent, argIndex int, offset int) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	userLen := networkSockaddrOutLen(event)
	if userLen == 0 {
		userLen = sockaddrPayloadMaxBytes
	}
	return sockaddrPayloadSection(event, payloadWindowSpec{
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		probeRet:  event.ProbeRetExit(),
	})
}

func sockaddrPayloadSection(event payloadEvent, spec payloadWindowSpec) []handler.PayloadSection {
	spec.kind = handler.PayloadKindStruct
	spec.maxLen = sockaddrPayloadMaxBytes
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      spec.kind,
		direction: spec.direction,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   spec.userLen,
		maxLen:    spec.maxLen,
		probeRet:  spec.probeRet,
	})
}

func socklenPayloadSection(event payloadEvent, direction handler.PayloadDirection, argIndex int, offset int, probeRet int32) []handler.PayloadSection {
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: direction,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   socklenPayloadSize,
		maxLen:    socklenPayloadSize,
		probeRet:  probeRet,
	})
}

func networkSockaddrOutLen(event payloadEvent) uint32 {
	outLen, outOK := socklenFromPayloadSource(event.source, sockaddrLenExitOffset)
	inLen, inOK := socklenFromPayloadSource(event.source, sockaddrLenEnterOffset)
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

func socklenFromPayloadSource(source payloadSource, offset int) (uint32, bool) {
	if source == nil {
		return 0, false
	}
	data, ok := source.PayloadWindow(offset, socklenPayloadSize)
	if !ok || len(data) < socklenPayloadSize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}
