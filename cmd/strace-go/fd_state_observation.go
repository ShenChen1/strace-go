package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func updateFDStateObservationFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	targetPID int,
	observations map[string]handler.FDStateObservation,
) {
	if !src.view.valid || src.view.ret < 0 || !isOpenedPathFDStateSyscall(scMeta.Name) {
		return
	}

	key := fdStateKey(targetPID, int32(src.view.ret))
	delete(observations, key)
	for _, section := range src.payloadSections {
		if section.Kind != handler.PayloadKindFDState ||
			section.Direction != handler.PayloadDirectionOut ||
			section.ArgIndex != handler.PayloadFDStateArgIndex ||
			section.ProbeRet != 0 {
			continue
		}
		observation, ok := handler.DecodeFDStateObservation(section.Data)
		if !ok || observation.FD != int32(src.view.ret) {
			return
		}
		observations[key] = observation
		return
	}
}
