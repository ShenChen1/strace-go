package main

import (
	"os"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type FDStateStore struct {
	paths   map[string]string
	offsets map[string]int64
	files   map[string]*os.File
}

type fdStateSource struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
	procTid         uint32
}

func newFDStateStore(targetPid int, paths map[string]string) *FDStateStore {
	if paths == nil {
		paths = make(map[string]string)
	}
	offsets, files := initFDTracking(targetPid, paths)
	return newFDStateStoreFromMaps(paths, offsets, files)
}

func newFDStateStoreFromMaps(paths map[string]string, offsets map[string]int64, files map[string]*os.File) *FDStateStore {
	store := &FDStateStore{paths: paths, offsets: offsets, files: files}
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
	if st.files == nil {
		st.files = make(map[string]*os.File)
	}
}

func (st *FDStateStore) PathMap() map[string]string {
	st.ensureMaps()
	return st.paths
}

func (st *FDStateStore) FileMap() map[string]*os.File {
	st.ensureMaps()
	return st.files
}

func (s *traceSession) fdStateStore() *FDStateStore {
	if s.fdState == nil {
		s.fdState = newFDStateStoreFromMaps(nil, nil, nil)
	}
	return s.fdState
}

func (st *FDStateStore) UpdateFromSyscall(ev syscallEventContext) {
	ev.updateFDState(st)
}

func (st *FDStateStore) updateFromSource(src fdStateSource, scMeta meta.Syscall, pathText string, targetPID int) {
	st.ensureMaps()
	updateFDMapFromSource(src, scMeta, pathText, targetPID, st.paths)
}

func updateFDMapFromSource(src fdStateSource, scMeta meta.Syscall, pathText string, targetPID int, fdMap map[string]string) {
	updateFdReturnMapFromView(src.view, scMeta, targetPID, fdMap)
	updateEventfdCountFromView(src.view, scMeta, targetPID, fdMap)
	updateOpenedPathFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
	updateDupFDMapFromView(src.view, scMeta, targetPID, fdMap)
	updatePipeFDMapFromPayload(src, scMeta, targetPID, fdMap)
	updateSocketpairFDMap(src, scMeta, targetPID, fdMap)
	updateNetlinkFDMap(src, scMeta, targetPID, fdMap)
	updateSocketFDMapFromView(src.view, scMeta, targetPID, fdMap)
	updateCwdFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
}

func (st *FDStateStore) CleanupClosedFDFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !view.valid || scMeta.Name != "close" || view.ret != 0 {
		return
	}
	st.ensureMaps()
	key := fdStateKey(statePID, int32(view.args[0]))
	delete(st.paths, key)
	delete(st.offsets, key)
	if f := st.files[key]; f != nil {
		f.Close()
		delete(st.files, key)
	}
}
