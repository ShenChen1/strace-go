package handler

import "fmt"

type testFDStateView struct {
	paths        map[string]string
	observations map[string]FDStateObservation
}

func (view testFDStateView) Path(pid int, fd int32) (string, bool) {
	path, ok := view.paths[fdStateTestKey(pid, fd)]
	return path, ok
}

func (view testFDStateView) Cwd(pid int) (string, bool) {
	path, ok := view.paths[fdStateTestCWDKey(pid)]
	return path, ok
}

func (view testFDStateView) Observation(pid int, fd int32) (FDStateObservation, bool) {
	observation, ok := view.observations[fdStateTestKey(pid, fd)]
	return observation, ok
}

type testEventFDStateView struct {
	paths        map[int32]string
	observations map[int32]FDStateObservation
	cwd          string
}

func (view testEventFDStateView) Path(fd int32) (string, bool) {
	path, ok := view.paths[fd]
	return path, ok
}

func (view testEventFDStateView) Cwd() (string, bool) {
	return view.cwd, view.cwd != ""
}

func (view testEventFDStateView) Observation(fd int32) (FDStateObservation, bool) {
	observation, ok := view.observations[fd]
	return observation, ok
}

func fdStateTestKey(pid int, fd int32) string {
	return fmt.Sprintf("%d:%d", pid, fd)
}

func fdStateTestCWDKey(pid int) string {
	return fmt.Sprintf("%d:cwd", pid)
}
