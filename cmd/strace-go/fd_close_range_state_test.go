package main

import (
	"testing"

	"golang.org/x/sys/unix"
	"strace-go/pkg/handler"
)

func TestFDStateStoreCloseRangeRemovesKnownState(t *testing.T) {
	store := closeRangeTestStore()

	newFDStateEvent("close_range", [6]uint64{3, 5, 0}, 0, nil).updateFDState(store)

	for _, fd := range []int32{3, 4, 5} {
		assertFDStateAbsent(t, store, fd)
	}
	assertFDStatePresent(t, store, 2)
	assertFDStatePresent(t, store, 6)
}

func TestFDStateStoreCloseRangeAcceptsUint32Max(t *testing.T) {
	store := closeRangeTestStore()
	last := uint64(^uint32(0))

	newFDStateEvent("close_range", [6]uint64{0, last, 0}, 0, nil).updateFDState(store)

	for _, fd := range []int32{2, 3, 4, 5, 6} {
		assertFDStateAbsent(t, store, fd)
	}
}

func TestFDStateStoreCloseRangeCloexecMarksKnownState(t *testing.T) {
	store := closeRangeTestStore()
	store.fdCloexec[fdStateKey(101, 3)] = false

	newFDStateEvent(
		"close_range",
		[6]uint64{3, 5, unix.CLOSE_RANGE_CLOEXEC},
		0,
		nil,
	).updateFDState(store)

	for _, fd := range []int32{3, 4, 5} {
		if got, ok := store.fdCloexec[fdStateKey(101, fd)]; !ok || !got {
			t.Fatalf("fd %d cloexec = %v, %v; want true, true", fd, got, ok)
		}
	}
	if got := store.fdCloexec[fdStateKey(101, 6)]; got {
		t.Fatal("fd outside close_range was changed")
	}

	store.CloseOnExecProcess(101)
	for _, fd := range []int32{3, 4, 5} {
		assertFDStateAbsent(t, store, fd)
	}
}

func TestFDStateStoreCloseRangeCombinationUsesCloexec(t *testing.T) {
	store := closeRangeTestStore()
	flags := uint64(unix.CLOSE_RANGE_UNSHARE | unix.CLOSE_RANGE_CLOEXEC)

	newFDStateEvent("close_range", [6]uint64{4, 4, flags}, 0, nil).updateFDState(store)

	if got, ok := store.fdCloexec[fdStateKey(101, 4)]; !ok || !got {
		t.Fatalf("combined flags cloexec = %v, %v; want true, true", got, ok)
	}
	assertFDStatePresent(t, store, 4)
}

func TestFDStateStoreCloseRangeRejectsInvalidMutation(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		ret  int64
	}{
		{name: "reverse range", args: [6]uint64{5, 3, 0}, ret: 0},
		{name: "unknown flags", args: [6]uint64{3, 5, 1}, ret: 0},
		{name: "failed syscall", args: [6]uint64{3, 5, 0}, ret: -22},
		{name: "suppressed probe", args: [6]uint64{3, 5, 0}, ret: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := closeRangeTestStore()
			event := newFDStateEvent("close_range", test.args, test.ret, nil)
			if test.name == "suppressed probe" {
				event.view.probeRetEnter = 3
			}

			event.updateFDState(store)
			assertFDStatePresent(t, store, 4)
			if got, ok := store.fdCloexec[fdStateKey(101, 4)]; !ok || got {
				t.Fatalf("fd 4 cloexec = %v, %v; want false, true", got, ok)
			}
		})
	}
}

func TestCloseRangeIsAnFDStateSyscall(t *testing.T) {
	event := newFDStateEvent("close_range", [6]uint64{3, 5}, 0, nil)
	event.shouldPrint = false

	if !event.isFDStateSyscall() || !event.shouldRunHandler() {
		t.Fatal("close_range must keep running when hidden by the syscall filter")
	}
}

func closeRangeTestStore() *FDStateStore {
	store := newFDStateStoreFromMaps(
		map[string]string{
			"101:2": "/tmp/keep",
			"101:3": "/tmp/remove-3",
			"101:4": "/tmp/remove-4",
			"101:5": "/tmp/remove-5",
			"101:6": "/tmp/keep-6",
		},
		map[string]int64{
			"101:2": 2,
			"101:3": 3,
			"101:4": 4,
			"101:5": 5,
			"101:6": 6,
		},
	)
	for fd := int32(2); fd <= 6; fd++ {
		store.fdStates[fdStateKey(101, fd)] = handler.FDStateObservation{
			FD: fd, Inode: uint64(fd),
		}
		store.fdCloexec[fdStateKey(101, fd)] = false
	}
	return store
}

func assertFDStatePresent(t *testing.T, store *FDStateStore, fd int32) {
	t.Helper()
	key := fdStateKey(101, fd)
	if _, ok := store.paths[key]; !ok {
		t.Fatalf("fd %d path state is missing", fd)
	}
	if _, ok := store.offsets[key]; !ok {
		t.Fatalf("fd %d offset state is missing", fd)
	}
	if _, ok := store.fdStates[key]; !ok {
		t.Fatalf("fd %d observation is missing", fd)
	}
}

func assertFDStateAbsent(t *testing.T, store *FDStateStore, fd int32) {
	t.Helper()
	key := fdStateKey(101, fd)
	if _, ok := store.paths[key]; ok {
		t.Fatalf("fd %d path state survived close_range", fd)
	}
	if _, ok := store.offsets[key]; ok {
		t.Fatalf("fd %d offset state survived close_range", fd)
	}
	if _, ok := store.fdStates[key]; ok {
		t.Fatalf("fd %d observation survived close_range", fd)
	}
	if _, ok := store.fdCloexec[key]; ok {
		t.Fatalf("fd %d cloexec state survived close_range", fd)
	}
}
