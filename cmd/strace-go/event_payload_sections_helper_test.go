package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func payloadSectionsForEvent(eventRaw *bpfEvent, scMeta meta.Syscall) []handler.PayloadSection {
	raw := newRawPayloadEventFromBPF(eventRaw)
	if raw.eventFlags&bpfEventFlagPayloadTLV != 0 {
		return payloadSectionsForRawPayloadEvent(raw, scMeta)
	}
	return payloadSectionsForPayloadEvent(newWindowPayloadEventFromRaw(raw), scMeta)
}
