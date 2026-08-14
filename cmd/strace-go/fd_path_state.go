package main

import (
	"fmt"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

var (
	_ event.EventFDPathReader    = eventFDStateView{}
	_ handler.EventFDStateReader = eventFDStateView{}
)

type fdPathOverlay struct {
	byArg   map[int]handler.FDPathSnapshot
	byFD    map[int32]handler.FDPathSnapshot
	cwdPath string
}

type eventFDStateView struct {
	paths  map[int32]string
	states map[int32]handler.FDStateObservation
	cwd    string
}

func (view eventFDStateView) Path(fd int32) (string, bool) {
	path, ok := view.paths[fd]
	return path, ok
}

func (view eventFDStateView) Cwd() (string, bool) {
	return view.cwd, view.cwd != ""
}

func (view eventFDStateView) Observation(fd int32) (handler.FDStateObservation, bool) {
	observation, ok := view.states[fd]
	return observation, ok
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
		if section.ArgIndex == handler.PayloadFDPathNestedArgIndex {
			if !snapshot.HasObservation || snapshot.Observation.FD < 0 {
				continue
			}
			if overlay.byFD == nil {
				overlay.byFD = make(map[int32]handler.FDPathSnapshot)
			}
			overlay.byFD[snapshot.Observation.FD] = snapshot
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

func (overlay fdPathOverlay) resolve(view syscallEventView) eventFDStateView {
	resolved := eventFDStateView{cwd: overlay.cwdPath}
	if !view.valid {
		return resolved
	}
	capacity := len(overlay.byArg) + len(overlay.byFD)
	if capacity == 0 {
		return resolved
	}
	resolved.paths = make(map[int32]string, capacity)
	resolved.states = make(map[int32]handler.FDStateObservation, capacity)
	for fd, snapshot := range overlay.byFD {
		resolved.paths[fd] = snapshot.Path
		resolved.states[fd] = snapshot.Observation
	}
	for argIndex, snapshot := range overlay.byArg {
		fd := int32(view.args[argIndex])
		if fd < 0 || fd == handler.AtFdcwd || snapshot.Path == "" {
			continue
		}
		resolved.paths[fd] = snapshot.Path
		if snapshot.HasObservation && snapshot.Observation.FD == fd {
			resolved.states[fd] = snapshot.Observation
		}
	}
	return resolved
}

func updateFDPathStateFromSource(
	src fdStateSource,
	targetPID int,
	paths map[string]string,
	observations map[string]handler.FDStateObservation,
) {
	overlay := fdPathOverlayFromSections(src.payloadSections)
	view := overlay.resolve(src.view)
	for fd, path := range view.paths {
		paths[fdStateKey(targetPID, fd)] = path
	}
	for fd, observation := range view.states {
		observations[fdStateKey(targetPID, fd)] = observation
	}
	if overlay.cwdPath != "" && src.view.valid {
		cwdKey := fmt.Sprintf("%d:cwd", targetPID)
		if _, known := paths[cwdKey]; !known {
			paths[cwdKey] = overlay.cwdPath
		}
	}
}

func initialTraceCommandFDSeed(targetPID int, cwd string) fdStateSeed {
	return newCwdFDStateSeed(targetPID, cwd)
}
