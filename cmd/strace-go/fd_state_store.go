package main

import (
	"fmt"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

var (
	_ event.FDPathReader    = (*FDStateStore)(nil)
	_ handler.FDStateReader = (*FDStateStore)(nil)
)

type FDStateStore struct {
	paths     map[string]string
	offsets   map[string]int64
	fdStates  map[string]handler.FDStateObservation
	fdCloexec map[string]bool
	runtime   handler.RuntimeServices
}

type fdStateSource struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
}

type fdStateUpdate struct {
	source    fdStateSource
	meta      meta.Syscall
	catalog   *meta.Catalog
	pathText  string
	targetPID int
}

func newFDStateStore(paths map[string]string) *FDStateStore {
	if paths == nil {
		paths = make(map[string]string)
	}
	store := &FDStateStore{
		paths:    paths,
		offsets:  make(map[string]int64),
		fdStates: make(map[string]handler.FDStateObservation),
		runtime:  handler.NewRuntime(),
	}
	store.ensureMaps()
	return store
}

func newFDStateStoreFromMaps(paths map[string]string, offsets map[string]int64) *FDStateStore {
	store := &FDStateStore{
		paths:    paths,
		offsets:  offsets,
		fdStates: make(map[string]handler.FDStateObservation),
		runtime:  handler.NewRuntime(),
	}
	store.ensureMaps()
	return store
}

func (st *FDStateStore) ensureMaps() {
	if st.paths == nil {
		st.paths = make(map[string]string)
	}
	if st.offsets == nil {
		st.offsets = make(map[string]int64)
	}
	if st.fdStates == nil {
		st.fdStates = make(map[string]handler.FDStateObservation)
	}
	if st.fdCloexec == nil {
		st.fdCloexec = make(map[string]bool)
	}
}

// Path returns the event-sourced path for one process descriptor.
func (st *FDStateStore) Path(pid int, fd int32) (string, bool) {
	if st == nil {
		return "", false
	}
	path, ok := st.paths[fdStateKey(pid, fd)]
	return path, ok
}

// Cwd returns the event-sourced working directory for one process.
func (st *FDStateStore) Cwd(pid int) (string, bool) {
	if st == nil {
		return "", false
	}
	path, ok := st.paths[fmt.Sprintf("%d:cwd", pid)]
	return path, ok
}

// Observation returns the event-time FD snapshot for one process descriptor.
func (st *FDStateStore) Observation(pid int, fd int32) (handler.FDStateObservation, bool) {
	if st == nil {
		return handler.FDStateObservation{}, false
	}
	observation, ok := st.fdStates[fdStateKey(pid, fd)]
	return observation, ok
}

func (st *FDStateStore) Runtime() handler.RuntimeServices {
	if st.runtime == nil {
		st.runtime = handler.NewRuntime()
	}
	return st.runtime
}

func (s *traceSession) fdStateStore() *FDStateStore {
	if s.fdState == nil {
		s.fdState = newFDStateStoreFromMaps(nil, nil)
	}
	return s.fdState
}

func (st *FDStateStore) update(update fdStateUpdate) {
	st.ensureMaps()
	updateFDPathStateFromSource(update.source, update.targetPID, st.paths, st.fdStates)
	updateFDStateObservationFromSource(update.source, update.meta, update.targetPID, st.fdStates)
	updateFDStateOffsetsFromSource(update.source, update.meta, update.targetPID, st.offsets)
	updateFDMapFromSource(update.source, update.meta, update.pathText, update.targetPID, st.paths, update.catalog)
	st.updateFDCloexecFromSource(update.source, update.meta, update.targetPID)
}

func updateFDMapFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	pathText string,
	targetPID int,
	fdMap map[string]string,
	catalog *meta.Catalog,
) {
	updateFdReturnMapFromSource(src, scMeta, targetPID, fdMap)
	updateEventfdCountFromView(src.view, scMeta, targetPID, fdMap)
	updateOpenedPathFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
	updateDupFDMapFromSource(src, scMeta, targetPID, fdMap)
	updatePipeFDMapFromPayload(src, scMeta, targetPID, fdMap)
	updateSocketpairFDMap(src, scMeta, targetPID, fdMap, catalog)
	updateNetlinkFDMap(src, scMeta, targetPID, fdMap)
	updateSocketFDMapFromView(src.view, scMeta, targetPID, fdMap, catalog)
	updateCwdFDMapFromView(src, scMeta, pathText, targetPID, fdMap)
}

func (st *FDStateStore) cleanupClosedFDFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || scMeta.Name != "close" || view.ret != 0 {
		return
	}
	st.ensureMaps()
	key := fdStateKey(statePID, int32(view.args[0]))
	delete(st.paths, key)
	delete(st.offsets, key)
	delete(st.fdStates, key)
	st.cleanupClosedFDCloexecFromView(view, scMeta, statePID)
}
