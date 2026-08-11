package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStoreTracksCloexecAcrossFDCreationSyscalls(t *testing.T) {
	const cloexec = uint64(0x80000)

	tests := []struct {
		name    string
		syscall string
		args    [6]uint64
		ret     int64
		payload []handler.PayloadSection
		wantFDs map[int32]bool
	}{
		{name: "open", syscall: "open", args: [6]uint64{0x1000, cloexec}, ret: 7, wantFDs: map[int32]bool{7: true}},
		{name: "openat", syscall: "openat", args: [6]uint64{^uint64(99), 0x1000, cloexec}, ret: 8, wantFDs: map[int32]bool{8: true}},
		{name: "creat", syscall: "creat", args: [6]uint64{0x1000, 0644}, ret: 9, wantFDs: map[int32]bool{9: false}},
		{name: "open_tree", syscall: "open_tree", args: [6]uint64{^uint64(99), 0x1000, cloexec}, ret: 10, wantFDs: map[int32]bool{10: true}},
		{
			name:    "openat2",
			syscall: "openat2",
			args:    [6]uint64{^uint64(99), 0x1000, 0x2000, 24},
			ret:     11,
			payload: openHowCloexecPayload(cloexec),
			wantFDs: map[int32]bool{11: true},
		},
		{name: "dup", syscall: "dup", args: [6]uint64{5}, ret: 12, wantFDs: map[int32]bool{12: false}},
		{name: "dup2", syscall: "dup2", args: [6]uint64{5, 13}, ret: 13, wantFDs: map[int32]bool{13: false}},
		{name: "dup3", syscall: "dup3", args: [6]uint64{5, 14, cloexec}, ret: 14, wantFDs: map[int32]bool{14: true}},
		{name: "fcntl dup", syscall: "fcntl", args: [6]uint64{5, 0, 20}, ret: 15, wantFDs: map[int32]bool{15: false}},
		{name: "fcntl dup cloexec", syscall: "fcntl", args: [6]uint64{5, 1030, 20}, ret: 16, wantFDs: map[int32]bool{16: true}},
		{
			name:    "pipe2",
			syscall: "pipe2",
			args:    [6]uint64{0x3000, cloexec},
			ret:     0,
			payload: fdArrayCloexecPayload(21, 22),
			wantFDs: map[int32]bool{21: true, 22: true},
		},
		{
			name:    "socketpair",
			syscall: "socketpair",
			args:    [6]uint64{1, cloexec, 0, 0x4000},
			ret:     0,
			payload: socketpairCloexecPayload(23, 24),
			wantFDs: map[int32]bool{23: true, 24: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFDStateStoreFromMaps(nil, nil)
			newFDStateEvent(test.syscall, test.args, test.ret, test.payload).updateFDState(store)

			for fd, want := range test.wantFDs {
				got, ok := store.FDCloexecMap()[fdStateKey(101, fd)]
				if !ok || got != want {
					t.Fatalf("fd %d cloexec = %v, %v; want %v, true", fd, got, ok, want)
				}
			}
		})
	}
}

func TestFDStateStoreTracksFcntlSetFDAndPreservesFailedMutation(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	store.FDCloexecMap()[fdStateKey(101, 5)] = false

	newFDStateEvent("fcntl", [6]uint64{5, 2, 1}, 0, nil).updateFDState(store)
	if got := store.FDCloexecMap()[fdStateKey(101, 5)]; !got {
		t.Fatal("F_SETFD(FD_CLOEXEC) did not enable close-on-exec")
	}

	newFDStateEvent("fcntl", [6]uint64{5, 2, 0}, 0, nil).updateFDState(store)
	if got := store.FDCloexecMap()[fdStateKey(101, 5)]; got {
		t.Fatal("F_SETFD without FD_CLOEXEC did not clear close-on-exec")
	}

	newFDStateEvent("fcntl", [6]uint64{5, 2, 1}, -1, nil).updateFDState(store)
	if got := store.FDCloexecMap()[fdStateKey(101, 5)]; got {
		t.Fatal("failed F_SETFD changed close-on-exec state")
	}
	newFDStateEvent("fcntl", [6]uint64{5, 2, 1}, 1, nil).updateFDState(store)
	if got := store.FDCloexecMap()[fdStateKey(101, 5)]; got {
		t.Fatal("non-zero F_SETFD return changed close-on-exec state")
	}
}

func TestFDStateStoreExecDropsCloexecAndUnknownState(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:cwd": "/known/cwd", "101:3": "keep", "101:4": "drop", "101:5": "unknown"},
		map[string]int64{"101:3": 3, "101:4": 4, "101:5": 5},
	)
	store.FDStateMap()["101:3"] = handler.FDStateObservation{FD: 3, Inode: 30}
	store.FDStateMap()["101:4"] = handler.FDStateObservation{FD: 4, Inode: 40}
	store.FDStateMap()["101:5"] = handler.FDStateObservation{FD: 5, Inode: 50}
	store.FDCloexecMap()["101:3"] = false
	store.FDCloexecMap()["101:4"] = true

	store.CloseOnExecProcess(101)

	if got := store.paths["101:3"]; got != "keep" {
		t.Fatalf("non-cloexec path = %q, want keep", got)
	}
	if got := store.paths["101:cwd"]; got != "/known/cwd" {
		t.Fatalf("cwd path = %q, want preserved cwd", got)
	}
	for _, key := range []string{"101:4", "101:5"} {
		if _, ok := store.paths[key]; ok {
			t.Fatalf("stale path %s survived exec", key)
		}
		if _, ok := store.offsets[key]; ok {
			t.Fatalf("stale offset %s survived exec", key)
		}
		if _, ok := store.FDStateMap()[key]; ok {
			t.Fatalf("stale observation %s survived exec", key)
		}
	}
	if got, ok := store.FDCloexecMap()["101:3"]; !ok || got {
		t.Fatalf("known non-cloexec state = %v, %v; want false, true", got, ok)
	}
	if _, ok := store.FDCloexecMap()["101:4"]; ok {
		t.Fatal("cloexec state survived exec")
	}
}

func TestFDStateStoreInheritsAndCleansCloexecState(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	store.FDCloexecMap()["100:3"] = true
	store.FDCloexecMap()["100:4"] = false

	store.InheritProcessState(100, 101)
	for key, want := range map[string]bool{"101:3": true, "101:4": false} {
		if got, ok := store.FDCloexecMap()[key]; !ok || got != want {
			t.Fatalf("inherited state[%s] = %v, %v; want %v, true", key, got, ok, want)
		}
	}

	store.CleanupProcess(101)
	if _, ok := store.FDCloexecMap()["101:3"]; ok {
		t.Fatal("child close-on-exec state was not cleaned")
	}
}

func TestFDStateStoreFailedFDReplacementPreservesPreviousCloexecState(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	store.FDCloexecMap()["101:7"] = true

	newFDStateEvent("dup2", [6]uint64{5, 7}, -1, nil).updateFDState(store)
	if got := store.FDCloexecMap()["101:7"]; !got {
		t.Fatal("failed dup2 changed target close-on-exec state")
	}

	newFDStateEvent("dup2", [6]uint64{5, 7}, 7, nil).updateFDState(store)
	if got := store.FDCloexecMap()["101:7"]; got {
		t.Fatal("successful dup2 did not clear target close-on-exec state")
	}
}

func newFDStateEvent(
	syscallName string,
	args [6]uint64,
	ret int64,
	payload []handler.PayloadSection,
) syscallEventContext {
	return syscallEventContext{
		view:            syscallEventView{valid: true, eventType: bpfEventTypeExit, args: args, ret: ret},
		statePID:        101,
		meta:            meta.Syscall{Name: syscallName},
		payloadSections: payload,
	}
}

func openHowCloexecPayload(flags uint64) []handler.PayloadSection {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], flags)
	return []handler.PayloadSection{{
		Kind: handler.PayloadKindStruct, Direction: handler.PayloadDirectionIn,
		ArgIndex: 2, UserLen: 24, CopiedLen: 24, ProbeRet: 0, Data: data,
	}}
}

func fdArrayCloexecPayload(first, second int32) []handler.PayloadSection {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], uint32(first))
	binary.LittleEndian.PutUint32(data[4:8], uint32(second))
	return []handler.PayloadSection{{
		Kind: handler.PayloadKindStruct, Direction: handler.PayloadDirectionOut,
		ArgIndex: 0, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: data,
	}}
}

func socketpairCloexecPayload(first, second int32) []handler.PayloadSection {
	sections := fdArrayCloexecPayload(first, second)
	sections[0].ArgIndex = 3
	return sections
}
