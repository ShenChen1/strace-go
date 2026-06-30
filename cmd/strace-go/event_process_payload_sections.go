package main

import "strace-go/pkg/handler"

const clone3PayloadMaxBytes = 256

func clone3PayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  0,
		offset:    handler.BpfEnterArgOffset,
		userLen:   uint32Clamped(eventRaw.Args[1]),
		maxLen:    clone3PayloadMaxBytes,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 0),
	})
}
