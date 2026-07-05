package main

import "strace-go/pkg/handler"

const (
	cachestatRangePayloadOffset = handler.BpfMiscArgOffset
	cachestatRangePayloadSize   = 16
	cachestatStatsPayloadSize   = 40
)

func cachestatPayloadSectionsFromSource(event payloadEvent, _ string) []handler.PayloadSection {
	sections := enterStructPayloadSectionFromSource(event, 1, cachestatRangePayloadOffset, cachestatRangePayloadSize)
	if event.IsExit() && event.Ret() >= 0 {
		sections = append(sections, exitStructPayloadSectionFromSource(event, 2, cachestatStatsPayloadSize)...)
	}
	return sections
}
