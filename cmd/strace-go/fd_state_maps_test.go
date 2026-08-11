package main

import "testing"

func TestFDStateStoreCopiesConstructorMaps(t *testing.T) {
	paths := map[string]string{"101:cwd": "/before", "101:3": "/input"}
	offsets := map[string]int64{"101:3": 17}
	store := newFDStateStoreFromMaps(paths, offsets)

	paths["101:cwd"] = "/after"
	paths["101:3"] = "/replaced"
	offsets["101:3"] = 99
	offsets["101:4"] = 23

	if got, ok := store.Cwd(101); !ok || got != "/before" {
		t.Fatalf("store cwd = %q, %v; want copied /before", got, ok)
	}
	if got, ok := store.Path(101, 3); !ok || got != "/input" {
		t.Fatalf("store path = %q, %v; want copied /input", got, ok)
	}
	if got := store.offsets[fdStateKey(101, 3)]; got != 17 {
		t.Fatalf("store offset = %d, want copied 17", got)
	}
	if _, ok := store.offsets[fdStateKey(101, 4)]; ok {
		t.Fatal("store unexpectedly observed offset added after construction")
	}
}

func TestNewFDStateStoreUsesConstructorOwnership(t *testing.T) {
	paths := map[string]string{"101:3": "/input"}
	store := newFDStateStore(paths)
	paths["101:3"] = "/after"

	if got, ok := store.Path(101, 3); !ok || got != "/input" {
		t.Fatalf("new store path = %q, %v; want copied /input", got, ok)
	}
}
