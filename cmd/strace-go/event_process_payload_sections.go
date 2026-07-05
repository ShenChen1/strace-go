package main

import "strace-go/pkg/handler"

const clone3PayloadMaxBytes = 256

func clone3PayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindStruct,
		direction: handler.PayloadDirectionIn,
		argIndex:  0,
		offset:    handler.BpfEnterArgOffset,
		userLen:   uint32Clamped(event.Arg(1)),
		maxLen:    clone3PayloadMaxBytes,
		probeRet:  event.ProbeRetEnterArg(0),
	})
}
