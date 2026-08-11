package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestFDStateStoreReaderIsNilSafeAndDoesNotInitializeState(t *testing.T) {
	store := &FDStateStore{}

	if _, ok := store.Path(101, 3); ok {
		t.Fatal("nil store path unexpectedly matched")
	}
	if _, ok := store.Cwd(101); ok {
		t.Fatal("nil store cwd unexpectedly matched")
	}
	if _, ok := store.Observation(101, 3); ok {
		t.Fatal("nil store observation unexpectedly matched")
	}
	if store.paths != nil || store.fdStates != nil || store.offsets != nil || store.fdCloexec != nil {
		t.Fatalf("reader initialized backing state: paths=%v states=%v offsets=%v cloexec=%v", store.paths, store.fdStates, store.offsets, store.fdCloexec)
	}
}

func TestFDStateStoreReaderReturnsEventSourcedValues(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": "/dev/null", "101:cwd": "/tmp"},
		nil,
	)
	store.fdStates["101:3"] = handler.FDStateObservation{FD: 3, Inode: 42}

	if got, ok := store.Path(101, 3); !ok || got != "/dev/null" {
		t.Fatalf("Path() = %q, %v; want /dev/null", got, ok)
	}
	if got, ok := store.Cwd(101); !ok || got != "/tmp" {
		t.Fatalf("Cwd() = %q, %v; want /tmp", got, ok)
	}
	if got, ok := store.Observation(101, 3); !ok || got.Inode != 42 {
		t.Fatalf("Observation() = %+v, %v; want inode 42", got, ok)
	}
}
