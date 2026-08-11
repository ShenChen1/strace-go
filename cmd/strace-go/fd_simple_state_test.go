package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestFDStateStoreTracksEventfdSnapshotsAndCloexec(t *testing.T) {
	tests := []struct {
		name    string
		syscall string
		args    [6]uint64
		ret     int64
		wantFD  int32
		wantOff int64
		wantClo bool
	}{
		{name: "eventfd", syscall: "eventfd", ret: 7, wantFD: 7, wantOff: 11},
		{name: "eventfd2", syscall: "eventfd2", args: [6]uint64{0, 0x100000000 | 0x80000}, ret: 8, wantFD: 8, wantOff: 13, wantClo: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFDStateStoreFromMaps(
				map[string]string{fdStateKey(101, test.wantFD): "stale"},
				map[string]int64{fdStateKey(101, test.wantFD): 99},
			)
			payload := fdStatePayloadSection(fdStateSnapshotBytes(
				test.wantFD, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
				0100600, 1, 2, uint64(test.wantFD)+100, test.wantOff,
			))
			event := newFDStateEvent(test.syscall, test.args, test.ret, []handler.PayloadSection{payload})

			event.updateFDState(store)
			event.updateFDOffsets(store)

			observation, ok := store.FDStateMap()[fdStateKey(101, test.wantFD)]
			if !ok || observation.FD != test.wantFD || observation.Offset != test.wantOff {
				t.Fatalf("eventfd observation = %+v, ok=%v", observation, ok)
			}
			if got := store.offsets[fdStateKey(101, test.wantFD)]; got != test.wantOff {
				t.Fatalf("eventfd offset = %d, want %d", got, test.wantOff)
			}
			if got := store.paths[fdStateKey(101, test.wantFD)]; got != "anon_inode:[eventfd]" {
				t.Fatalf("eventfd path = %q, want anon_inode marker", got)
			}
			if got := store.FDCloexecMap()[fdStateKey(101, test.wantFD)]; got != test.wantClo {
				t.Fatalf("eventfd cloexec = %v, want %v", got, test.wantClo)
			}
		})
	}
}

func TestFDStateStoreEventfdSnapshotStateBoundaries(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:7": "stale"},
		map[string]int64{"101:7": 99},
	)
	store.FDStateMap()["101:7"] = handler.FDStateObservation{FD: 7, Inode: 70}
	store.FDCloexecMap()["101:7"] = true

	tests := []struct {
		name      string
		ret       int64
		payload   []handler.PayloadSection
		wantClear bool
	}{
		{name: "failed syscall", ret: -1, wantClear: false},
		{name: "missing snapshot", ret: 7, wantClear: true},
		{
			name:      "wrong snapshot fd",
			ret:       7,
			wantClear: true,
			payload: []handler.PayloadSection{fdStatePayloadSection(fdStateSnapshotBytes(
				8, handler.FDStateFlagIdentity|handler.FDStateFlagOffset, 0100600, 1, 2, 80, 1,
			))},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetFDStateStoreForEventfdFailure(store)
			event := newFDStateEvent("eventfd2", [6]uint64{0, 0x80000}, test.ret, test.payload)
			event.updateFDState(store)
			event.updateFDOffsets(store)

			if test.wantClear {
				assertFDStateAbsent(t, store, 7)
				if _, ok := store.FDStateMap()["101:8"]; ok {
					t.Fatal("mismatched eventfd snapshot installed an unrelated observation")
				}
				if _, ok := store.paths["101:7"]; ok {
					t.Fatal("failed eventfd replacement kept stale path")
				}
				if _, ok := store.offsets["101:7"]; ok {
					t.Fatal("failed eventfd replacement kept stale offset")
				}
				if _, ok := store.FDCloexecMap()["101:7"]; ok {
					t.Fatal("failed eventfd replacement kept stale cloexec state")
				}
				return
			}
			if _, ok := store.FDStateMap()["101:7"]; !ok {
				t.Fatal("failed eventfd syscall changed old observation")
			}
			if got := store.paths["101:7"]; got != "stale" {
				t.Fatalf("failed eventfd syscall path = %q, want stale", got)
			}
			if got := store.offsets["101:7"]; got != 99 {
				t.Fatalf("failed eventfd syscall offset = %d, want 99", got)
			}
			if got, ok := store.FDCloexecMap()["101:7"]; !ok || !got {
				t.Fatalf("failed eventfd syscall cloexec = %v, ok=%v", got, ok)
			}
		})
	}
}

func TestEventfdIsAnFDStateSyscall(t *testing.T) {
	event := newFDStateEvent("eventfd2", [6]uint64{0, 0x80000}, 7, nil)
	event.shouldPrint = false
	if !event.isFDStateSyscall() || !event.shouldRunHandler() {
		t.Fatal("eventfd2 must keep running when hidden by the syscall filter")
	}
}

func resetFDStateStoreForEventfdFailure(store *FDStateStore) {
	store.paths["101:7"] = "stale"
	store.offsets["101:7"] = 99
	store.FDStateMap()["101:7"] = handler.FDStateObservation{FD: 7, Inode: 70}
	store.FDCloexecMap()["101:7"] = true
}
