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
	_ fdFlagDecoder         = (*meta.Catalog)(nil)
)

// fdFlagDecoder exposes only the xlat capability needed by FD metadata updates.
type fdFlagDecoder interface {
	DecodeFlags(value uint64, tableName string) string
}

type FDStateStore struct {
	paths     map[string]string
	offsets   map[string]int64
	fdStates  map[string]handler.FDStateObservation
	fdCloexec map[string]bool
}

type fdStateSource struct {
	view            syscallEventView
	payloadSections []handler.PayloadSection
}

type fdStateUpdate struct {
	source      fdStateSource
	meta        meta.Syscall
	flagDecoder fdFlagDecoder
	pathText    string
	targetPID   int
}

func newFDStateStore(paths map[string]string) *FDStateStore {
	return newFDStateStoreFromMaps(paths, nil)
}

func newFDStateStoreFromMaps(paths map[string]string, offsets map[string]int64) *FDStateStore {
	store := &FDStateStore{
		paths:    copyFDStatePaths(paths),
		offsets:  copyFDStateOffsets(offsets),
		fdStates: make(map[string]handler.FDStateObservation),
	}
	store.ensureMaps()
	return store
}

func newFDStateStoreFromSeed(seed fdStateSeed) *FDStateStore {
	return newFDStateStoreFromMaps(seed.paths, nil)
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

func (s *traceSession) fdStateStore() traceFDStateOwner {
	if s == nil {
		return nil
	}
	return s.dependencies.FDState
}

func shouldApplyFDStateUpdate(update fdStateUpdate) bool {
	return shouldApplyFDStateEvent(
		update.source.view,
		update.meta.Name,
		update.source.payloadSections,
	)
}

func shouldApplyFDStateEvent(
	view syscallEventView,
	syscallName string,
	payloadSections []handler.PayloadSection,
) bool {
	return shouldApplyFDStateEventWithTraits(
		view,
		payloadSections,
		syscallEventTraitsForView(view, syscallName),
	)
}

func shouldApplyFDStateEventWithTraits(
	view syscallEventView,
	payloadSections []handler.PayloadSection,
	traits syscallEventTraits,
) bool {
	if len(payloadSections) > 0 {
		return true
	}
	if !view.valid {
		return false
	}
	if traits&syscallEventTraitStateRead != 0 {
		return view.ret == 8
	}
	return traits&syscallEventTraitState != 0
}

func (st *FDStateStore) ApplyFDState(update fdStateUpdate) {
	if !shouldApplyFDStateUpdate(update) {
		return
	}
	st.ensureMaps()
	updateFDPathStateFromSource(update.source, update.targetPID, st.paths, st.fdStates)
	updateFDStateObservationFromSource(update.source, update.meta, update.targetPID, st.fdStates)
	updateFDStateOffsetsFromSource(update.source, update.meta, update.targetPID, st.offsets)
	updateFDMapFromSource(update.source, update.meta, update.pathText, update.targetPID, st.paths, update.flagDecoder)
	st.updateFDCloexecFromSource(update.source, update.meta, update.targetPID)
}

func updateFDMapFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	pathText string,
	targetPID int,
	fdMap map[string]string,
	flagDecoder fdFlagDecoder,
) {
	updateFdReturnMapFromSource(src, scMeta, targetPID, fdMap)
	updateEventfdCountFromView(src.view, scMeta, targetPID, fdMap)
	updateOpenedPathFDMapFromView(src.view, scMeta, pathText, targetPID, fdMap)
	updateDupFDMapFromSource(src, scMeta, targetPID, fdMap)
	updatePipeFDMapFromPayload(src, scMeta, targetPID, fdMap)
	updateSocketpairFDMap(src, scMeta, targetPID, fdMap, flagDecoder)
	updateNetlinkFDMap(src, scMeta, targetPID, fdMap)
	updateSocketFDMapFromSource(src, scMeta, targetPID, fdMap, flagDecoder)
	updateCwdFDMapFromView(src, scMeta, pathText, targetPID, fdMap)
}

func (st *FDStateStore) CleanupClosedFD(update fdCloseUpdate) {
	st.cleanupClosedFDFromView(update.view, update.meta, update.statePID)
}

func shouldCleanupClosedFDEvent(view syscallEventView, syscallName string) bool {
	return shouldCleanupClosedFDEventWithTraits(
		view,
		syscallEventTraitsForView(view, syscallName),
	)
}

func shouldCleanupClosedFDEventWithTraits(
	view syscallEventView,
	traits syscallEventTraits,
) bool {
	return view.valid && traits&syscallEventTraitClose != 0 && view.ret == 0
}

func (st *FDStateStore) cleanupClosedFDFromView(view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !shouldCleanupClosedFDEvent(view, scMeta.Name) {
		return
	}
	st.ensureMaps()
	key := fdStateKey(statePID, int32(view.args[0]))
	delete(st.paths, key)
	delete(st.offsets, key)
	delete(st.fdStates, key)
	st.cleanupClosedFDCloexecFromView(view, scMeta, statePID)
}
