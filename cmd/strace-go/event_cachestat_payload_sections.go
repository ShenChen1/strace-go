package main

import "strace-go/pkg/handler"

const (
	cachestatRangePayloadOffset = handler.BpfMiscArgOffset
	cachestatRangePayloadSize   = 16
	cachestatStatsPayloadSize   = 40
)

func cachestatPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := enterStructPayloadSection(eventRaw, 1, cachestatRangePayloadOffset, cachestatRangePayloadSize)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, exitStructPayloadSection(eventRaw, 2, cachestatStatsPayloadSize)...)
	}
	return sections
}
