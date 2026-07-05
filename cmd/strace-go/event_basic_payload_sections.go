package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

func prlimitPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 2, handler.BpfEnterArgOffset, rlimitPayloadStructSize)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, exitStructPayloadSection(eventRaw, 3, rlimitPayloadStructSize)...)
	}
	return sections
}

func robustListPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	sections := exitStructPayloadSectionAt(eventRaw, 1, handler.BpfExitArgOffset, robustListPayloadWordSize)
	return append(sections, exitStructPayloadSectionAt(eventRaw, 2, handler.BpfExitArgOffset+16, robustListPayloadWordSize)...)
}

func waitidPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	sections := exitStructPayloadSectionAt(eventRaw, 2, handler.BpfExitArgOffset, waitidSiginfoPayloadSize)
	return append(sections, exitStructPayloadSectionAt(eventRaw, 4, handler.BpfExitArgOffset+136, waitidRusagePayloadSize)...)
}

func sendfilePayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 2, handler.BpfMiscArgOffset, offsetPointerPayloadSize)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, exitStructPayloadSection(eventRaw, 2, offsetPointerPayloadSize)...)
	}
	return sections
}

func copyFileRangePayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 1, handler.BpfMiscArgOffset, offsetPointerPayloadSize)
	return append(sections, enterStructPayloadSection(eventRaw, 3, handler.BpfMiscArgOffset+8, offsetPointerPayloadSize)...)
}

type stringPayloadWindowSpec struct {
	argIndex int
	offset   int
	maxBytes int
}

func stringPayloadSectionFromWindow(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	return stringPayloadSectionFromWindowSpec(eventRaw, stringPayloadWindowSpec{
		argIndex: argIndex,
		maxBytes: 4097,
	})
}

func stringPayloadSectionFromSource(event payloadEvent, argIndex int) []handler.PayloadSection {
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: argIndex,
		maxBytes: 4097,
	})
}

func stringPayloadSectionFromWindowSpec(eventRaw *bpfEvent, spec stringPayloadWindowSpec) []handler.PayloadSection {
	if eventRaw.EventType != bpfEventTypeEnter && eventRaw.EventType != bpfEventTypeExit {
		return nil
	}
	return stringPayloadSectionFromSourceSpec(newFixedPayloadEvent(eventRaw), spec)
}

func stringPayloadSectionFromSourceSpec(event payloadEvent, spec stringPayloadWindowSpec) []handler.PayloadSection {
	if event.raw != nil && event.raw.EventType != bpfEventTypeEnter && event.raw.EventType != bpfEventTypeExit {
		return nil
	}
	if event.source == nil {
		return nil
	}
	data, ok := event.source.PayloadWindow(spec.offset, spec.maxBytes)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSectionFromSource(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: handler.PayloadDirectionIn,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   uint32(len(data)),
		probeRet:  event.ProbeRetEnterArg(spec.argIndex),
	}, data)
	return []handler.PayloadSection{section}
}

func exitBytesPayloadSectionFromRet(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
		return nil
	}
	userLen := uint32Clamped(uint64(eventRaw.Ret))
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   userLen,
		maxLen:    userLen,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func exitStructPayloadSection(eventRaw *bpfEvent, argIndex int, size uint32) []handler.PayloadSection {
	return exitStructPayloadSectionAt(eventRaw, argIndex, handler.BpfExitArgOffset, size)
}

func exitStructPayloadSectionAt(eventRaw *bpfEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret < 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  eventRaw.ProbeRetExit,
	})
}

func enterStructPayloadSection(eventRaw *bpfEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	return enterStructPayloadSectionFromSource(newFixedPayloadEvent(eventRaw), argIndex, offset, size)
}

func enterStructPayloadSectionFromSource(event payloadEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  event.ProbeRetEnterArg(argIndex),
	})
}
