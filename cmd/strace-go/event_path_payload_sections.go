package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

const (
	pathPayloadPrimaryOffset   = 0
	pathPayloadSecondaryOffset = 512
	pathPayloadMaxBytes        = 512
)

type pathPayloadSpec struct {
	argIndex int
	offset   int
}

func dualPathPayloadSectionsForEvent(eventRaw *bpfEvent, firstArg int, secondArg int) []handler.PayloadSection {
	sections := stringPayloadSectionFromWindowAt(eventRaw, pathPayloadSpec{
		argIndex: firstArg,
		offset:   pathPayloadPrimaryOffset,
	})
	return append(sections, stringPayloadSectionFromWindowAt(eventRaw, pathPayloadSpec{
		argIndex: secondArg,
		offset:   pathPayloadSecondaryOffset,
	})...)
}

func stringPayloadSectionFromWindowAt(eventRaw *bpfEvent, spec pathPayloadSpec) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, spec.offset, pathPayloadMaxBytes)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: handler.PayloadDirectionIn,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   uint32(len(data)),
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, spec.argIndex),
	}, data)
	return []handler.PayloadSection{section}
}
