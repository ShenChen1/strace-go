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
	if isFcntlFDStateSyscall(scMeta.Name) && !isFcntlFDStateCommand(src.view.args) {
		return
	}
	if isFDArrayFDStateSyscall(scMeta.Name) {
		if src.view.ret != 0 {
			return
		}
		updateFDArrayStateObservations(src, targetPID, observations)
		return
	}

	key := fdStateKey(targetPID, int32(src.view.ret))
	if fdStateTargetReplaced(src.view, scMeta.Name) {
		delete(observations, key)
	}
	for _, section := range src.payloadSections {
		observation, ok := fdStateObservationFromSection(section)
		if !ok || observation.FD != int32(src.view.ret) {
			return
		}
		observations[key] = observation
		return
	}
}

func updateFDArrayStateObservations(
	src fdStateSource,
	targetPID int,
	observations map[string]handler.FDStateObservation,
) {
	for _, section := range src.payloadSections {
		observation, ok := fdStateObservationFromSection(section)
		if !ok {
			continue
		}
		observations[fdStateKey(targetPID, observation.FD)] = observation
	}
}

func fdStateObservationFromSection(section handler.PayloadSection) (handler.FDStateObservation, bool) {
	if section.Kind != handler.PayloadKindFDState ||
		section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != handler.PayloadFDStateArgIndex ||
		section.ProbeRet != 0 {
		return handler.FDStateObservation{}, false
	}
	observation, ok := handler.DecodeFDStateObservation(section.Data)
	return observation, ok && observation.FD >= 0
}

func isFDStateObservationSyscall(scName string) bool {
	return isOpenedPathFDStateSyscall(scName) ||
		isDuplicatedFDStateSyscall(scName) || isFDArrayFDStateSyscall(scName) ||
		isFcntlFDStateSyscall(scName)
}

func isFDArrayFDStateSyscall(scName string) bool {
	switch scName {
	case "pipe", "pipe2", "socketpair":
		return true
	default:
		return false
	}
}

func isFcntlFDStateSyscall(scName string) bool {
	return scName == "fcntl" || scName == "fcntl64"
}

func isFcntlFDStateCommand(args [6]uint64) bool {
	switch uint32(args[1]) {
	case 0, 1030:
		return true
	default:
		return false
	}
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
	if isOpenedPathFDStateSyscall(scName) || scName == "dup" || isFcntlFDStateSyscall(scName) {
		return true
	}
	if scName == "dup2" || scName == "dup3" {
		return int32(view.args[0]) != int32(view.args[1])
	}
	return false
}
