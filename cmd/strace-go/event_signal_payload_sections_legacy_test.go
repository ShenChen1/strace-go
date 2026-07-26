package main

import "strace-go/pkg/handler"

const (
	signalSigsetPayloadSize    = 8
	signalSigactionPayloadSize = 32
)

func signalPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "rt_sigaction":
		sections := enterStructPayloadSectionFromSource(event, 1, payloadEnterArgOffset, signalSigactionPayloadSize)
		if event.IsExit() && event.Ret() >= 0 {
			sections = append(sections, exitStructPayloadSectionFromSource(event, 2, signalSigactionPayloadSize)...)
		}
		return sections
	case "rt_sigprocmask":
		sections := enterStructPayloadSectionFromSource(event, 1, payloadEnterArgOffset, signalSigsetPayloadSize)
		if event.IsExit() && event.Ret() >= 0 {
			sections = append(sections, exitStructPayloadSectionFromSource(event, 2, signalSigsetPayloadSize)...)
		}
		return sections
	case "rt_sigsuspend":
		return enterStructPayloadSectionFromSource(event, 0, payloadEnterArgOffset, signalSigsetPayloadSize)
	default:
		return nil
	}
}
