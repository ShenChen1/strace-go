package main

import (
	"strace-go/pkg/handler"
)

func iovecArgPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	return iovecPayloadSectionFromSource(event, 1, 2, handler.BpfEnterArgOffset)
}

func processVMPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := iovecPayloadSectionFromSource(event, 1, 2, handler.BpfEnterArgOffset)
	return append(sections, iovecPayloadSectionFromSource(event, 3, 4, handler.BpfMiscArgOffset)...)
}

func processMadvisePayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	return iovecPayloadSectionFromSource(event, 1, 2, handler.BpfEnterArgOffset)
}

func iovecPayloadSectionFromSource(event payloadEvent, argIndex int, countIndex int, offset int) []handler.PayloadSection {
	userLen := iovecUserLen(event.Arg(countIndex))
	if userLen == 0 {
		return nil
	}
	maxLen := int(userLen)
	if maxLen > iovecSectionMaxBytes {
		maxLen = iovecSectionMaxBytes
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindIovec,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   userLen,
		maxLen:    uint32(maxLen),
		probeRet:  event.ProbeRetEnterArg(argIndex),
	})
}
