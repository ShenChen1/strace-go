package main

import "strace-go/pkg/handler"

const (
	signalSigsetPayloadSize    = 8
	signalSigactionPayloadSize = 32
)

func signalPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "rt_sigaction":
		sections := enterStructPayloadSection(eventRaw, 1, handler.BpfEnterArgOffset, signalSigactionPayloadSize)
		if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
			sections = append(sections, exitStructPayloadSection(eventRaw, 2, signalSigactionPayloadSize)...)
		}
		return sections
	case "rt_sigprocmask":
		sections := enterStructPayloadSection(eventRaw, 1, handler.BpfEnterArgOffset, signalSigsetPayloadSize)
		if isExitEvent(eventRaw) && eventRaw.Ret >= 0 {
			sections = append(sections, exitStructPayloadSection(eventRaw, 2, signalSigsetPayloadSize)...)
		}
		return sections
	case "rt_sigsuspend":
		return enterStructPayloadSection(eventRaw, 0, handler.BpfEnterArgOffset, signalSigsetPayloadSize)
	default:
		return nil
	}
}
