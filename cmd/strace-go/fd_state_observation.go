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
	if !src.view.valid || src.view.ret < 0 || !isFDStateObservationSyscall(scMeta.Name) {
		return
	}

	key := fdStateKey(targetPID, int32(src.view.ret))
	if fdStateTargetReplaced(src.view, scMeta.Name) {
		delete(observations, key)
	}
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

func isFDStateObservationSyscall(scName string) bool {
	return isOpenedPathFDStateSyscall(scName) || isDuplicatedFDStateSyscall(scName)
}

func isDuplicatedFDStateSyscall(scName string) bool {
	switch scName {
	case "dup", "dup2", "dup3":
		return true
	default:
		return false
	}
}

func fdStateTargetReplaced(view syscallEventView, scName string) bool {
	if isOpenedPathFDStateSyscall(scName) || scName == "dup" {
		return true
	}
	if scName == "dup2" || scName == "dup3" {
		return int32(view.args[0]) != int32(view.args[1])
	}
	return false
}
