package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

const (
	prctlNamePayloadSize   = 16
	prctlUint32PayloadSize = 4
)

func prctlPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	option := uint32(eventRaw.Args[0])
	switch {
	case option == 15:
		return prctlStringPayloadSection(eventRaw, handler.PayloadDirectionIn, handler.BpfEnterArgOffset, eventRaw.ProbeRetEnter)
	case option == 16:
		if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
			return prctlStringPayloadSection(eventRaw, handler.PayloadDirectionOut, handler.BpfExitArgOffset, eventRaw.ProbeRetExit)
		}
	case prctlHasUint32Out(option):
		if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
			return exitStructPayloadSection(eventRaw, 1, prctlUint32PayloadSize)
		}
	}
	return nil
}

func prctlStringPayloadSection(
	eventRaw *bpfEvent,
	direction handler.PayloadDirection,
	offset int,
	probeRet int32,
) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, offset, prctlNamePayloadSize)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	return []handler.PayloadSection{newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: direction,
		argIndex:  1,
		offset:    offset,
		userLen:   uint32(len(data)),
		probeRet:  probeRet,
	}, data)}
}

func prctlHasUint32Out(option uint32) bool {
	switch option {
	case 1, 5, 9, 11, 19, 25, 37:
		return true
	default:
		return false
	}
}
