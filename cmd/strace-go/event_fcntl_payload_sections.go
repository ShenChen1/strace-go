package main

import "strace-go/pkg/handler"

func fcntlPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	size := fcntlPayloadSize(eventRaw.Args[1])
	if size == 0 {
		return nil
	}

	sections := enterStructPayloadSection(eventRaw, 2, handler.BpfEnterArgOffset, size)
	if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
		sections = append(sections, exitStructPayloadSection(eventRaw, 2, size)...)
	}
	return sections
}

func fcntlPayloadSize(cmd uint64) uint32 {
	switch uint32(cmd) {
	case 15, 16, 19, 20, 21, 22, 23, 24, 1035, 1036, 1037, 1038, 1039, 1040, 1043, 1044:
		return 8
	case 5, 6, 7, 12, 13, 14, 36, 37, 38:
		return 32
	default:
		return 0
	}
}
