package main

import (
	"fmt"
	"path/filepath"

	"strace-go/pkg/handler"
)

type fdPathOverlay struct {
	byArg   map[int]handler.FDPathSnapshot
	cwdPath string
}

func fdPathOverlayFromSections(sections []handler.PayloadSection) fdPathOverlay {
	overlay := fdPathOverlay{}
	for _, section := range sections {
		if section.Kind != handler.PayloadKindFDPath ||
			section.Direction != handler.PayloadDirectionIn ||
			section.ProbeRet != 0 {
			continue
		}
		if section.ArgIndex == handler.PayloadFDPathCwdArgIndex {
			path, ok := handler.DecodeFDPathOnly(section.Data)
			if ok {
				overlay.cwdPath = path
			}
			continue
		}
		snapshot, ok := handler.DecodeFDPathSnapshot(section.Data)
		if !ok {
			continue
		}
		if section.ArgIndex < 0 || section.ArgIndex >= 6 {
			continue
		}
		if overlay.byArg == nil {
			overlay.byArg = make(map[int]handler.FDPathSnapshot)
		}
		overlay.byArg[section.ArgIndex] = snapshot
	}
	return overlay
}

func (overlay fdPathOverlay) resolve(view syscallEventView) (
	map[int32]string,
	map[int32]handler.FDStateObservation,
) {
	if !view.valid || len(overlay.byArg) == 0 {
		return nil, nil
	}
	paths := make(map[int32]string, len(overlay.byArg))
	states := make(map[int32]handler.FDStateObservation, len(overlay.byArg))
	for argIndex, snapshot := range overlay.byArg {
		fd := int32(view.args[argIndex])
		if fd < 0 || fd == handler.AtFdcwd || snapshot.Path == "" {
			continue
		}
		paths[fd] = snapshot.Path
		if snapshot.HasObservation && snapshot.Observation.FD == fd {
			states[fd] = snapshot.Observation
		}
	}
	return paths, states
}

func updateFDPathStateFromSource(
	src fdStateSource,
	targetPID int,
	paths map[string]string,
	observations map[string]handler.FDStateObservation,
) {
	overlay := fdPathOverlayFromSections(src.payloadSections)
	eventPaths, eventStates := overlay.resolve(src.view)
	for fd, path := range eventPaths {
		paths[fdStateKey(targetPID, fd)] = path
	}
	for fd, observation := range eventStates {
		observations[fdStateKey(targetPID, fd)] = observation
	}
	if overlay.cwdPath != "" && src.view.valid {
		cwdKey := fmt.Sprintf("%d:cwd", targetPID)
		if _, known := paths[cwdKey]; !known {
			paths[cwdKey] = overlay.cwdPath
		}
	}
}

func initialTraceCommandFDMap(targetPID int, cwd string) map[string]string {
	paths := make(map[string]string)
	if targetPID <= 0 || cwd == "" {
		return paths
	}
	cleaned := filepath.Clean(cwd)
	if !filepath.IsAbs(cleaned) {
		return paths
	}
	paths[fmt.Sprintf("%d:cwd", targetPID)] = cleaned
	return paths
}
