package main

import "strace-go/pkg/handler"

const (
	capabilityHeaderPayloadSize = 8
	capabilityDataPayloadSize   = 24
)

func capabilityPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 0, handler.BpfEnterArgOffset, capabilityHeaderPayloadSize)
	switch scName {
	case "capget":
		return append(sections, exitStructPayloadSectionFromSource(event, 1, capabilityDataPayloadSize)...)
	case "capset":
		return append(sections, enterStructPayloadSectionFromSource(event, 1, handler.BpfMiscArgOffset, capabilityDataPayloadSize)...)
	default:
		return sections
	}
}
