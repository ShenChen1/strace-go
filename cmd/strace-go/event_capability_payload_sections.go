package main

import "strace-go/pkg/handler"

const (
	capabilityHeaderPayloadSize = 8
	capabilityDataPayloadSize   = 24
)

func capabilityPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 0, handler.BpfEnterArgOffset, capabilityHeaderPayloadSize)
	switch scName {
	case "capget":
		return append(sections, exitStructPayloadSection(eventRaw, 1, capabilityDataPayloadSize)...)
	case "capset":
		return append(sections, enterStructPayloadSection(eventRaw, 1, handler.BpfMiscArgOffset, capabilityDataPayloadSize)...)
	default:
		return sections
	}
}
