package main

import "strace-go/pkg/handler"

const bpfAttrPayloadMaxBytes = 512

func bpfPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	if event.Arg(1) == 0 || event.Arg(2) == 0 {
		return nil
	}
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  1,
		offset:    payloadEnterArgOffset,
		userLen:   uint32Clamped(event.Arg(2)),
		maxLen:    bpfAttrPayloadMaxBytes,
		probeRet:  event.ProbeRetEnterArg(1),
	})
}
