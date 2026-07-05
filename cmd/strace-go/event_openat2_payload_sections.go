package main

import "strace-go/pkg/handler"

const (
	openat2HowPayloadOffset = 4096
	openat2HowPayloadMax    = 64
)

func openat2PayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := stringPayloadSectionFromSource(event, 1)
	return append(sections, enterStructPayloadSectionFromSource(
		event,
		2,
		openat2HowPayloadOffset,
		uint32Clamped(event.Arg(3)),
	)...)
}
