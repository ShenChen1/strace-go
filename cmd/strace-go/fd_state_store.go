package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type FDStateStore struct {
	paths   map[string]string
	offsets map[string]int64
	runtime handler.RuntimeServices
}

type fdStateSource struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
	procTid         uint32
}

type fdStateUpdate struct {
	source    fdStateSource
	meta      meta.Syscall
	pathText  string
	targetPID int
}

func newFDStateStore(targetPid int, paths map[string]string) *FDStateStore {
	if paths == nil {
		paths = make(map[string]string)
	}
	offsets := initFDTracking(targetPid, paths)
	return newFDStateStoreFromMaps(paths, offsets)
}

func newFDStateStoreFromMaps(paths map[string]string, offsets map[string]int64) *FDStateStore {
	store := &FDStateStore{paths: paths, offsets: offsets, runtime: handler.NewRuntime()}
	store.ensureMaps()
	return store
}

func newFDStateStoreWithRuntime(paths map[string]string, offsets map[string]int64, runtime handler.RuntimeServices) *FDStateStore {
	store := &FDStateStore{paths: paths, offsets: offsets, runtime: runtime}
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
}

func (st *FDStateStore) PathMap() map[string]string {
	st.ensureMaps()
	return st.paths
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
	updateFDMapFromSource(update.source, update.meta, update.pathText, update.targetPID, st.paths, st.Runtime())
}

func updateFDMapFromSource(src fdStateSource, scMeta meta.Syscall, pathText string, targetPID int, fdMap map[string]string, runtime handler.RuntimeServices) {
	updateFdReturnMapFromView(src.view, scMeta, targetPID, fdMap, runtime)
	updateEventfdCountFromView(src.view, scMeta, targetPID, fdMap)
	updateOpenedPathFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
	updateDupFDMapFromView(src.view, scMeta, targetPID, fdMap)
	updatePipeFDMapFromPayload(src, scMeta, targetPID, fdMap)
	updateSocketpairFDMap(src, scMeta, targetPID, fdMap)
	updateNetlinkFDMap(src, scMeta, targetPID, fdMap)
	updateSocketFDMapFromView(src.view, scMeta, targetPID, fdMap)
	updateCwdFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
}

func (st *FDStateStore) cleanupClosedFDFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || scMeta.Name != "close" || view.ret != 0 {
		return
	}
	st.ensureMaps()
	key := fdStateKey(statePID, int32(view.args[0]))
	delete(st.paths, key)
	delete(st.offsets, key)
}
