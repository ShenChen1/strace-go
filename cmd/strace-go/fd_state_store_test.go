package main

import (
	"os"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStoreCleanupClosedFDRemovesOwnedState(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove", "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
	)

	store.cleanupClosedFDFromView(syscallEventView{
		valid: true,
		args:  [6]uint64{3},
		ret:   0,
	}, meta.Syscall{Name: "close"}, 101)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("closed fd path was not removed")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("closed fd offset was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("unrelated fd path = %q, want /tmp/keep", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEventViewForOpenedPath(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, ret: 7},
		statePID: 101,
		meta:     meta.Syscall{Name: "openat"},
		pathText: `"/tmp/view-path"`,
	}

	ev.updateFDState(store)

	if got := store.paths["101:7"]; got != "/tmp/view-path" {
		t.Fatalf("view fd path = %q, want /tmp/view-path", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw fd path = %q, want empty", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEventViewForDup(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:5": "/tmp/source"}, nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, args: [6]uint64{5}, ret: 6},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup"},
	}

	ev.updateFDState(store)

	if got := store.paths["101:6"]; got != "/tmp/source" {
		t.Fatalf("view dup path = %q, want /tmp/source", got)
	}
	if got := store.paths["101:4"]; got != "" {
		t.Fatalf("raw dup path = %q, want empty", got)
	}
}

func TestSyscallEventContextUpdateFDStateUsesEffectiveMetadata(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 201, tid: 201, ret: 7},
		statePID: 101,
		pathText: `"/tmp/effective-path"`,
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "openat"},
		},
	}

	ev.updateFDState(store)

	if got := store.paths["101:7"]; got != "/tmp/effective-path" {
		t.Fatalf("effective metadata fd path = %q, want /tmp/effective-path", got)
	}
}

func TestSyscallEventContextUpdateFDStateBuildsPayloadWithEffectiveMetadata(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	fdData := fdArrayJSONData(uint32(readEnd.Fd()), uint32(writeEnd.Fd()))
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view: syscallEventView{
			valid:        true,
			tid:          uint32(os.Getpid()),
			eventType:    bpfEventTypeExit,
			ret:          0,
			probeRetExit: 0,
		},
		statePID: 101,
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  0,
			UserLen:   uint32(len(fdData)),
			CopiedLen: uint32(len(fdData)),
			ProbeRet:  0,
			Data:      fdData,
		}},
	}
	ev.handlerContext = &handler.Context{
		ScMeta: meta.Syscall{Name: "pipe"},
	}

	ev.updateFDState(store)

	readKey := fdStateKey(101, int32(readEnd.Fd()))
	writeKey := fdStateKey(101, int32(writeEnd.Fd()))
	if store.paths[readKey] == "" {
		t.Fatalf("fd path %q missing after effective metadata payload update", readKey)
	}
	if store.paths[writeKey] == "" {
		t.Fatalf("fd path %q missing after effective metadata payload update", writeKey)
	}
}

func TestSyscallEventContextUpdateFDStateSkipsPipeWithoutPayload(t *testing.T) {
	for _, name := range []string{"pipe", "pipe2"} {
		t.Run(name, func(t *testing.T) {
			store := newFDStateStoreFromMaps(make(map[string]string), nil)
			ev := syscallEventContext{
				view: syscallEventView{
					valid:     true,
					tid:       uint32(os.Getpid()),
					eventType: bpfEventTypeExit,
					ret:       0,
				},
				statePID: 101,
				meta:     meta.Syscall{Name: name},
			}

			ev.updateFDState(store)

			if len(store.paths) != 0 {
				t.Fatalf("fd paths = %d, want 0 without fd array payload section", len(store.paths))
			}
		})
	}
}

func TestSyscallEventContextUpdateFDStateSkipsPointerPathText(t *testing.T) {
	store := newFDStateStoreFromMaps(make(map[string]string), nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 1234, tid: 1234, args: [6]uint64{rawAtFdcwd, 0x1000}, ret: 7},
		statePID: 101,
		meta:     meta.Syscall{Name: "openat"},
		pathText: "0x1000",
	}

	ev.updateFDState(store)

	if len(store.paths) != 0 {
		t.Fatalf("fd paths = %d, want 0 without decoded path payload", len(store.paths))
	}
}

func TestSyscallEventContextUpdateFDStateSkipsNetlinkWithoutPayload(t *testing.T) {
	tests := []struct {
		name          string
		args          [6]uint64
		probeRetEnter int32
		probeRetExit  int32
	}{
		{name: "bind", args: [6]uint64{7, 0x3000, 8}, probeRetEnter: 0, probeRetExit: -1},
		{name: "getsockname", args: [6]uint64{7, 0x3000, 0x4000}, probeRetEnter: -1, probeRetExit: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFDStateStoreFromMaps(make(map[string]string), nil)
			ev := syscallEventContext{
				view: syscallEventView{
					valid:         true,
					pid:           1234,
					tid:           1234,
					args:          test.args,
					eventType:     bpfEventTypeExit,
					ret:           0,
					probeRetEnter: test.probeRetEnter,
					probeRetExit:  test.probeRetExit,
				},
				statePID: 101,
				meta:     meta.Syscall{Name: test.name},
			}

			ev.updateFDState(store)

			if len(store.paths) != 0 {
				t.Fatalf("fd paths = %d, want 0 without netlink sockaddr payload section", len(store.paths))
			}
		})
	}
}

func TestSyscallExitEffectsCleanupClosedFDUsesEventView(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove", "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
	)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{3}, ret: 0},
		statePID: 101,
		meta:     meta.Syscall{Name: "close"},
	}

	newTraceSessionSyscallExitEffects(nil, store, store).CleanupClosedFD(ev)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("view-selected fd path was not removed")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("view-selected fd offset was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("raw-selected fd path = %q, want untouched /tmp/keep", got)
	}
	if got := store.offsets["101:4"]; got != 99 {
		t.Fatalf("raw-selected fd offset = %d, want untouched 99", got)
	}
}

func TestSyscallEventContextCleanupClosedFDUsesEffectiveMetadata(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/tmp/remove"},
		map[string]int64{"101:3": 12},
	)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{3}, ret: 0},
		statePID: 101,
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "close"},
		},
	}

	ev.cleanupClosedFD(store)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("effective metadata close did not remove fd path")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("effective metadata close did not remove fd offset")
	}
}

func TestFDStateStorePersistsEventTimeObservationAndOffset(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	data := fdStateSnapshotBytes(7, handler.FDStateFlagIdentity|handler.FDStateFlagOffset, 0100644, 1, 2, 3, 27)
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			eventType: bpfEventTypeExit,
			args:      [6]uint64{rawAtFdcwd, 0x1000},
			ret:       7,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "openat"},
		pathText: `"/tmp/event-time"`,
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			CopiedLen: handler.FDStateSnapshotSize,
			ProbeRet:  0,
			Data:      data,
		}},
	}

	ev.updateFDState(store)
	ev.updateFDOffsets(store)

	observation, ok := store.fdStates["101:7"]
	if !ok || observation.Inode != 3 || observation.Offset != 27 {
		t.Fatalf("stored observation = %+v, ok=%v", observation, ok)
	}
	if got := store.offsets["101:7"]; got != 27 {
		t.Fatalf("stored offset = %d, want event-time offset 27", got)
	}
	if got := store.paths["101:7"]; got != "/tmp/event-time" {
		t.Fatalf("stored path = %q, want event-time path", got)
	}
}

func TestFDStateStoreFailedObservationClearsReusedFD(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	store.fdStates["101:7"] = handler.FDStateObservation{FD: 7, Inode: 99}
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			eventType: bpfEventTypeExit,
			ret:       7,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "open"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			ProbeRet:  -14,
		}},
	}

	ev.updateFDState(store)
	if _, ok := store.fdStates["101:7"]; ok {
		t.Fatal("failed event-time observation retained stale state for reused fd")
	}
}

func TestFDStateStoreInheritsAndCleansEventTimeObservation(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	store.fdStates["100:1"] = handler.FDStateObservation{FD: 1, Inode: 42}

	store.InheritProcessState(100, 101)
	if got := store.fdStates["101:1"].Inode; got != 42 {
		t.Fatalf("child event-time inode = %d, want 42", got)
	}

	store.CleanupProcess(101)
	if _, ok := store.fdStates["101:1"]; ok {
		t.Fatal("child event-time observation was not cleaned")
	}
}

func TestFDStateStorePersistsDupEventTimeObservation(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:5": "/tmp/source", "101:8": "/tmp/old-target"},
		map[string]int64{"101:5": 11, "101:8": 99},
	)
	store.fdStates["101:8"] = handler.FDStateObservation{FD: 8, Inode: 99}
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			args:  [6]uint64{5},
			ret:   8,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			CopiedLen: handler.FDStateSnapshotSize,
			ProbeRet:  0,
			Data:      fdStateSnapshotBytes(8, handler.FDStateFlagIdentity|handler.FDStateFlagOffset, 0100644, 1, 2, 3, 11),
		}},
	}

	ev.updateFDState(store)
	ev.updateFDOffsets(store)

	observation, ok := store.fdStates["101:8"]
	if !ok || observation.Inode != 3 || observation.Offset != 11 {
		t.Fatalf("dup observation = %+v, ok=%v", observation, ok)
	}
	if got := store.paths["101:8"]; got != "/tmp/source" {
		t.Fatalf("dup target path = %q, want source path", got)
	}
	if got := store.offsets["101:8"]; got != 11 {
		t.Fatalf("dup target offset = %d, want shared source offset", got)
	}
}

func TestFDStateStoreDupTargetFailureClearsReusedState(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:7": "/tmp/old-target"},
		map[string]int64{"101:7": 42},
	)
	store.fdStates["101:7"] = handler.FDStateObservation{FD: 7, Inode: 99}
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			args:  [6]uint64{5, 7},
			ret:   7,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup2"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			CopiedLen: 0,
			ProbeRet:  -14,
		}},
	}

	ev.updateFDState(store)
	ev.updateFDOffsets(store)

	if _, ok := store.fdStates["101:7"]; ok {
		t.Fatal("failed dup2 observation retained overwritten target state")
	}
	if _, ok := store.paths["101:7"]; ok {
		t.Fatal("failed dup2 path retained overwritten target state")
	}
	if _, ok := store.offsets["101:7"]; ok {
		t.Fatal("failed dup2 offset retained overwritten target state")
	}
}

func TestFDStateStoreDupSelfFailurePreservesState(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:7": "/tmp/self"},
		map[string]int64{"101:7": 42},
	)
	store.fdStates["101:7"] = handler.FDStateObservation{FD: 7, Inode: 99}
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			args:  [6]uint64{7, 7},
			ret:   7,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "dup2"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			CopiedLen: 0,
			ProbeRet:  -14,
		}},
	}

	ev.updateFDState(store)
	ev.updateFDOffsets(store)

	if got := store.paths["101:7"]; got != "/tmp/self" {
		t.Fatalf("dup2 self path = %q, want preserved path", got)
	}
	if got := store.offsets["101:7"]; got != 42 {
		t.Fatalf("dup2 self offset = %d, want preserved offset", got)
	}
	if _, ok := store.fdStates["101:7"]; !ok {
		t.Fatal("dup2 self observation was removed")
	}
}
