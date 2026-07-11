package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

func prlimitPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 2, handler.BpfEnterArgOffset, rlimitPayloadStructSize)
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, exitStructPayloadSectionFromSource(event, 3, rlimitPayloadStructSize)...)
	}
	return sections
}

func robustListPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	sections := exitStructPayloadSectionAtFromSource(event, 1, handler.BpfExitArgOffset, robustListPayloadWordSize)
	return append(sections, exitStructPayloadSectionAtFromSource(event, 2, handler.BpfExitArgOffset+16, robustListPayloadWordSize)...)
}

func waitidPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	sections := exitStructPayloadSectionAtFromSource(event, 2, handler.BpfExitArgOffset, waitidSiginfoPayloadSize)
	return append(sections, exitStructPayloadSectionAtFromSource(event, 4, handler.BpfExitArgOffset+136, waitidRusagePayloadSize)...)
}

func sendfilePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 2, handler.BpfMiscArgOffset, offsetPointerPayloadSize)
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, exitStructPayloadSectionFromSource(event, 2, offsetPointerPayloadSize)...)
	}
	return sections
}

func copyFileRangePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 1, handler.BpfMiscArgOffset, offsetPointerPayloadSize)
	return append(sections, enterStructPayloadSectionFromSource(event, 3, handler.BpfMiscArgOffset+8, offsetPointerPayloadSize)...)
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
	if !event.IsSyscallEvent() {
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
	return exitBytesPayloadSectionFromSourceRet(newFixedPayloadEvent(eventRaw), argIndex)
}

func exitBytesPayloadSectionFromSourceRet(event payloadEvent, argIndex int) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() <= 0 {
		return nil
	}
	userLen := uint32Clamped(uint64(event.Ret()))
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   userLen,
		maxLen:    userLen,
		probeRet:  event.ProbeRetExit(),
	})
}

func exitStructPayloadSection(eventRaw *bpfEvent, argIndex int, size uint32) []handler.PayloadSection {
	return exitStructPayloadSectionFromSource(newFixedPayloadEvent(eventRaw), argIndex, size)
}

func exitStructPayloadSectionFromSource(event payloadEvent, argIndex int, size uint32) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    handler.BpfExitArgOffset,
		userLen:   size,
		maxLen:    size,
		probeRet:  event.ProbeRetExit(),
	})
}

func exitStructPayloadSectionAt(eventRaw *bpfEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	return exitStructPayloadSectionAtFromSource(newFixedPayloadEvent(eventRaw), argIndex, offset, size)
}

func exitStructPayloadSectionAtFromSource(event payloadEvent, argIndex int, offset int, size uint32) []handler.PayloadSection {
	if !event.IsExit() || event.Ret() < 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionOut,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   size,
		maxLen:    size,
		probeRet:  event.ProbeRetExit(),
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
