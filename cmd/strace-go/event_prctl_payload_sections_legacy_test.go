package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

const (
	prctlNamePayloadSize   = 16
	prctlUint32PayloadSize = 4
)

func prctlPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	option := uint32(event.Arg(0))
	switch {
	case option == 15:
		return prctlStringPayloadSectionFromSource(event, handler.PayloadDirectionIn, payloadEnterArgOffset, event.ProbeRetEnterArg(1))
	case option == 16:
		if event.IsExit() && event.Ret() >= 0 {
			return prctlStringPayloadSectionFromSource(event, handler.PayloadDirectionOut, payloadExitArgOffset, event.ProbeRetExit())
		}
	case prctlHasUint32Out(option):
		if event.IsExit() && event.Ret() >= 0 {
			return exitStructPayloadSectionFromSource(event, 1, prctlUint32PayloadSize)
		}
	}
	return nil
}

func prctlStringPayloadSectionFromSource(
	event payloadEvent,
	direction handler.PayloadDirection,
	offset int,
	probeRet int32,
) []handler.PayloadSection {
	if event.source == nil {
		return nil
	}
	data, ok := event.source.PayloadWindow(offset, prctlNamePayloadSize)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	return []handler.PayloadSection{newPayloadSectionFromSource(event.source, payloadWindowSpec{
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
