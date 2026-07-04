package main

import (
	"os"

	"strace-go/pkg/meta"
)

type FDStateStore struct {
	paths   map[string]string
	offsets map[string]int64
	files   map[string]*os.File
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

func (st *FDStateStore) UpdateFromEvent(eventRaw *bpfEvent, scMeta meta.Syscall, rawStrArg string, statePID int) {
	st.ensureMaps()
	updateFDMap(eventRaw, scMeta, rawStrArg, statePID, st.paths)
}

func (st *FDStateStore) CleanupClosedFD(eventRaw *bpfEvent, scMeta meta.Syscall, statePID int) {
	if scMeta.Name != "close" || eventRaw.Ret != 0 {
		return
	}
	st.ensureMaps()
	key := fdStateKey(statePID, int32(eventRaw.Args[0]))
	delete(st.paths, key)
	delete(st.offsets, key)
	if f := st.files[key]; f != nil {
		f.Close()
		delete(st.files, key)
	}
}
