package main

import (
	"encoding/binary"

	"strace-go/pkg/handler"
)

const (
	aioPayloadPointerSize    = 8
	aioPayloadIocbSize       = 64
	aioPayloadEventsElemSize = 32
	aioPayloadMaxBytes       = 512
	aioPayloadSigsetOffset   = payloadMiscArgOffset + 16
	aioPayloadSigmaskOffset  = payloadMiscArgOffset + 32
	aioPayloadSigmaskProbe   = 13
)

func aioPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "io_setup":
		return aioSetupPayloadSections(event)
	case "io_submit":
		return aioSubmitPayloadSections(event)
	case "io_cancel":
		if event.Arg(1) == 0 {
			return nil
		}
		return enterStructPayloadSectionFromSource(event, 1, payloadEnterArgOffset, aioPayloadIocbSize)
	case "io_getevents":
		return aioGeteventsPayloadSections(event, false)
	case "io_pgetevents", "io_pgetevents_time64":
		return aioGeteventsPayloadSections(event, true)
	default:
		return nil
	}
}

func aioSetupPayloadSections(event payloadEvent) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 || event.Arg(1) == 0 {
		return nil
	}
	return exitStructPayloadSectionFromSource(event, 1, aioPayloadPointerSize)
}

func aioSubmitPayloadSections(event payloadEvent) []handler.PayloadSection {
	count := int64(event.Arg(1))
	if count <= 0 || event.Arg(2) == 0 {
		return nil
	}
	userLen := structArrayUserLen(uint64(count), aioPayloadPointerSize)
	sections := payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  2,
		offset:    payloadEnterArgOffset,
		userLen:   userLen,
		maxLen:    aioPayloadMaxBytes,
		probeRet:  event.ProbeRetEnterArg(2),
	})
	return append(sections, aioSubmitIocbPayloadSections(event, count)...)
}

func aioSubmitIocbPayloadSections(event payloadEvent, count int64) []handler.PayloadSection {
	if event.ProbeRetEnterArg(2) != 0 || event.source == nil {
		return nil
	}
	pointers, ok := event.source.PayloadWindow(payloadEnterArgOffset, aioPayloadMaxBytes)
	if !ok {
		return nil
	}

	limit := int(count)
	if limit > 2 {
		limit = 2
	}
	sections := make([]handler.PayloadSection, 0, limit)
	for i := 0; i < limit; i++ {
		pointerOff := i * aioPayloadPointerSize
		if len(pointers) < pointerOff+aioPayloadPointerSize {
			break
		}
		userPtr := binary.LittleEndian.Uint64(pointers[pointerOff : pointerOff+aioPayloadPointerSize])
		if userPtr == 0 {
			continue
		}
		section := aioSubmitIocbPayloadSection(event, i, userPtr)
		if section.CopiedLen > 0 {
			sections = append(sections, section)
		}
	}
	return sections
}

func aioSubmitIocbPayloadSection(event payloadEvent, index int, userPtr uint64) handler.PayloadSection {
	if event.source == nil {
		return handler.PayloadSection{}
	}
	offset := payloadMiscArgOffset + index*aioPayloadIocbSize
	data, ok := event.source.PayloadWindow(offset, aioPayloadIocbSize)
	if !ok || aioPayloadAllBytesZero(data) {
		return handler.PayloadSection{}
	}
	section := newPayloadSectionFromSource(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  handler.AioSubmitIocbPayloadArgBase + index,
		offset:    offset,
		userLen:   aioPayloadIocbSize,
		maxLen:    aioPayloadIocbSize,
		probeRet:  0,
	}, data)
	section.UserPtr = userPtr
	return section
}

func aioGeteventsPayloadSections(event payloadEvent, includeSigset bool) []handler.PayloadSection {
	var sections []handler.PayloadSection
	if event.Arg(4) != 0 {
		sections = enterStructPayloadSectionFromSource(event, 4, payloadMiscArgOffset, timespecPayloadStructSize)
	}
	if includeSigset && event.Arg(5) != 0 {
		sections = append(sections, enterStructPayloadSectionFromSource(event, 5, aioPayloadSigsetOffset, timespecPayloadStructSize)...)
		sections = append(sections, aioPgeteventsSigmaskPayloadSection(event)...)
	}
	if event.IsExit() && event.Ret() > 0 {
		sections = append(sections, exitStructArrayPayloadSectionFromSourceRet(
			event,
			3,
			aioPayloadEventsElemSize,
			aioPayloadMaxBytes,
		)...)
	}
	return sections
}

func aioPgeteventsSigmaskPayloadSection(event payloadEvent) []handler.PayloadSection {
	if event.ProbeRetEnterArg(5) != 0 || aioNestedProbeFailed(event.ProbeRetEnter(), aioPayloadSigmaskProbe) {
		return nil
	}
	if event.source == nil {
		return nil
	}
	sigsetData, ok := event.source.PayloadWindow(aioPayloadSigsetOffset, timespecPayloadStructSize)
	if !ok {
		return nil
	}
	sigmaskPtr := binary.LittleEndian.Uint64(sigsetData[0:8])
	sigsetSize := binary.LittleEndian.Uint64(sigsetData[8:16])
	if sigmaskPtr == 0 || sigsetSize == 0 || sigsetSize > 8 {
		return nil
	}
	data, ok := event.source.PayloadWindow(aioPayloadSigmaskOffset, int(sigsetSize))
	if !ok {
		return nil
	}
	section := newPayloadSectionFromSource(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  5,
		offset:    aioPayloadSigmaskOffset,
		userLen:   uint32(sigsetSize),
		maxLen:    uint32(sigsetSize),
		probeRet:  0,
	}, data)
	section.UserPtr = sigmaskPtr
	return []handler.PayloadSection{section}
}

func aioNestedProbeFailed(probeRet int32, bit int) bool {
	if probeRet >= 0 {
		return false
	}
	if probeRet == -1 {
		return true
	}
	mask := uint32(-probeRet - 1)
	return (mask & (uint32(1) << uint(bit))) != 0
}

func aioPayloadAllBytesZero(data []byte) bool {
	for _, x := range data {
		if x != 0 {
			return false
		}
	}
	return true
}
