package main

import "testing"

func TestFDStateSeedCopiesInputPaths(t *testing.T) {
	paths := map[string]string{"101:cwd": "/before"}
	seed := newFDStateSeed(paths)
	paths["101:cwd"] = "/after"

	store := newFDStateStoreFromSeed(seed)
	if got, ok := store.Cwd(101); !ok || got != "/before" {
		t.Fatalf("seed cwd = %q, %v; want copied /before", got, ok)
	}
}

func TestFDStateSeedMergePreservesOverwriteOrder(t *testing.T) {
	seed := newFDStateSeed(map[string]string{"101:cwd": "/command"})
	seed.merge(newFDStateSeed(map[string]string{"101:cwd": "/attach"}))

	store := newFDStateStoreFromSeed(seed)
	if got, ok := store.Cwd(101); !ok || got != "/attach" {
		t.Fatalf("merged cwd = %q, %v; want attach seed", got, ok)
	}
}

func TestFDStateStoreCopiesSeedBeforeEventConsumption(t *testing.T) {
	seed := newFDStateSeed(map[string]string{"101:cwd": "/before"})
	store := newFDStateStoreFromSeed(seed)
	seed.paths["101:cwd"] = "/mutated-after-build"

	if got, ok := store.Cwd(101); !ok || got != "/before" {
		t.Fatalf("store cwd = %q, %v after seed mutation; want /before", got, ok)
	}
}

func TestInitialTraceCommandFDSeedRejectsInvalidCWD(t *testing.T) {
	for _, test := range []struct {
		name string
		pid  int
		cwd  string
	}{
		{name: "invalid pid", pid: 0, cwd: "/tmp"},
		{name: "relative cwd", pid: 101, cwd: "relative"},
		{name: "empty cwd", pid: 101},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed := initialTraceCommandFDSeed(test.pid, test.cwd)
			if len(seed.paths) != 0 {
				t.Fatalf("seed paths = %v, want empty", seed.paths)
			}
		})
	}
}
