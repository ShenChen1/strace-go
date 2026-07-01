package main

import "strace-go/pkg/handler"

const bpfAttrPayloadMaxBytes = 512

func bpfPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	if eventRaw.Args[1] == 0 || eventRaw.Args[2] == 0 {
		return nil
	}
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  1,
		offset:    handler.BpfEnterArgOffset,
		userLen:   uint32Clamped(eventRaw.Args[2]),
		maxLen:    bpfAttrPayloadMaxBytes,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 1),
	})
}
