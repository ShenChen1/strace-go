package main

import "strace-go/pkg/handler"

const (
	openat2HowPayloadOffset = 4096
	openat2HowPayloadMax    = 64
)

func openat2PayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := stringPayloadSectionFromWindow(eventRaw, 1)
	return append(sections, payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  2,
		offset:    openat2HowPayloadOffset,
		userLen:   uint32Clamped(eventRaw.Args[3]),
		maxLen:    openat2HowPayloadMax,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 2),
	})...)
}
