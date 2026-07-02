package main

import (
	"os"
	"testing"

	"strace-go/pkg/meta"
)

func TestFDStateStoreCleanupClosedFDRemovesOwnedState(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fd-state-*")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer tmp.Close()

	store := newFDStateStoreFromMaps(
		map[string]string{"101:3": tmp.Name(), "101:4": "/tmp/keep"},
		map[string]int64{"101:3": 12, "101:4": 99},
		map[string]*os.File{"101:3": tmp},
	)

	store.CleanupClosedFD(&bpfEvent{
		Args: [6]uint64{3},
		Ret:  0,
	}, meta.Syscall{Name: "close"}, 101)

	if _, ok := store.paths["101:3"]; ok {
		t.Fatal("closed fd path was not removed")
	}
	if _, ok := store.offsets["101:3"]; ok {
		t.Fatal("closed fd offset was not removed")
	}
	if _, ok := store.files["101:3"]; ok {
		t.Fatal("closed fd file was not removed")
	}
	if got := store.paths["101:4"]; got != "/tmp/keep" {
		t.Fatalf("unrelated fd path = %q, want /tmp/keep", got)
	}
}
