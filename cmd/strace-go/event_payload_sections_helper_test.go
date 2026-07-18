package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func payloadSectionsForEvent(eventRaw *bpfEvent, scMeta meta.Syscall) []handler.PayloadSection {
	return payloadSectionsForRawPayloadEvent(newRawPayloadEventFromBPF(eventRaw), scMeta)
}
