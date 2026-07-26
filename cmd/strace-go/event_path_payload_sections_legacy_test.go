package main

import "strace-go/pkg/handler"

const (
	pathPayloadPrimaryOffset   = 0
	pathPayloadSecondaryOffset = 512
	pathPayloadMaxBytes        = 512
)

type pathPayloadSpec struct {
	argIndex int
	offset   int
}

func dualPathPayloadSectionsFromSource(event payloadEvent, firstArg int, secondArg int) []handler.PayloadSection {
	sections := stringPayloadSectionFromSourceAt(event, pathPayloadSpec{
		argIndex: firstArg,
		offset:   pathPayloadPrimaryOffset,
	})
	return append(sections, stringPayloadSectionFromSourceAt(event, pathPayloadSpec{
		argIndex: secondArg,
		offset:   pathPayloadSecondaryOffset,
	})...)
}

func stringPayloadSectionFromSourceAt(event payloadEvent, spec pathPayloadSpec) []handler.PayloadSection {
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: spec.argIndex,
		offset:   spec.offset,
		maxBytes: pathPayloadMaxBytes,
	})
}
