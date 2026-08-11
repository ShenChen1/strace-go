package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type FDStateStore struct {
	paths    map[string]string
	offsets  map[string]int64
	runtime  handler.RuntimeServices
	metadata handler.FDMetadataServices
}

type fdStateSource struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
	procTid         uint32
	metadata        handler.FDMetadataServices // session-scoped OS metadata adapter
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
	runtime := handler.NewRuntime()
	offsets := initFDTracking(targetPid, paths, runtime)
	return newFDStateStoreWithServices(paths, offsets, runtime, runtime)
}

func newFDStateStoreFromMaps(paths map[string]string, offsets map[string]int64) *FDStateStore {
	runtime := handler.NewRuntime()
	store := newFDStateStoreWithServices(paths, offsets, runtime, runtime)
	store.ensureMaps()
	return store
}

func newFDStateStoreWithRuntime(paths map[string]string, offsets map[string]int64, runtime handler.RuntimeServices) *FDStateStore {
	var metadata handler.FDMetadataServices
	if candidate, ok := runtime.(handler.FDMetadataServices); ok {
		metadata = candidate
	}
	return newFDStateStoreWithServices(paths, offsets, runtime, metadata)
}

func newFDStateStoreWithServices(
	paths map[string]string,
	offsets map[string]int64,
	runtime handler.RuntimeServices,
	metadata handler.FDMetadataServices,
) *FDStateStore {
	store := &FDStateStore{paths: paths, offsets: offsets, runtime: runtime, metadata: metadata}
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

func (st *FDStateStore) Metadata() handler.FDMetadataServices {
	if st.metadata == nil {
		if candidate, ok := st.Runtime().(handler.FDMetadataServices); ok {
			st.metadata = candidate
		}
	}
	return st.metadata
}

func (s *traceSession) fdStateStore() *FDStateStore {
	if s.fdState == nil {
		s.fdState = newFDStateStoreFromMaps(nil, nil)
	}
	return s.fdState
}

func (st *FDStateStore) update(update fdStateUpdate) {
	st.ensureMaps()
	source := update.source
	source.metadata = st.Metadata()
	updateFDMapFromSource(source, update.meta, update.pathText, update.targetPID, st.paths)
}

func updateFDMapFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	pathText string,
	targetPID int,
	fdMap map[string]string,
) {
	metadata := src.metadata
	updateFdReturnMapFromView(src.view, scMeta, targetPID, fdMap, metadata)
	updateEventfdCountFromView(src.view, scMeta, targetPID, fdMap)
	updateOpenedPathFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
	updateDupFDMapFromView(src.view, scMeta, targetPID, fdMap)
	updatePipeFDMapFromPayload(src, scMeta, targetPID, fdMap)
	updateSocketpairFDMap(src, scMeta, targetPID, fdMap)
	updateNetlinkFDMap(src, scMeta, targetPID, fdMap)
	updateSocketFDMapFromView(src.view, scMeta, targetPID, fdMap, metadata)
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
}
