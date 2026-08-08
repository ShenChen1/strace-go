package main

import "testing"

func TestEventStatePIDUsesViewPIDOrTargetFallback(t *testing.T) {
	session := &traceSession{targetPid: 101}

	if got := session.eventStatePID(traceEventEnvelope{valid: true, pid: 202}); got != 202 {
		t.Fatalf("eventStatePID(view pid) = %d, want 202", got)
	}
	if got := session.eventStatePID(traceEventEnvelope{valid: true}); got != 101 {
		t.Fatalf("eventStatePID(zero pid) = %d, want target pid 101", got)
	}
	if got := session.eventStatePID(traceEventEnvelope{}); got != 101 {
		t.Fatalf("eventStatePID(invalid view) = %d, want target pid 101", got)
	}
}

func TestFDStateStoreInheritProcessStateCopiesFDAndCWD(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{
		"100:cwd": "/tmp",
		"100:1":   "/tmp/out",
		"200:1":   "/other",
	}, map[string]int64{
		"100:1": 42,
		"200:1": 7,
	})

	store.InheritProcessState(100, 101)

	if got := store.paths["101:cwd"]; got != "/tmp" {
		t.Fatalf("child cwd = %q, want /tmp", got)
	}
	if got := store.paths["101:1"]; got != "/tmp/out" {
		t.Fatalf("child fd target = %q, want /tmp/out", got)
	}
	if got := store.offsets["101:1"]; got != 42 {
		t.Fatalf("child fd offset = %d, want 42", got)
	}
	if got := store.paths["200:1"]; got != "/other" {
		t.Fatalf("unrelated fd target = %q, want /other", got)
	}
}

func TestFDStateStoreCleanupProcessRemovesFDState(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{
		"100:cwd": "/tmp",
		"100:1":   "/tmp/out",
		"200:1":   "/other",
	}, map[string]int64{
		"100:1": 42,
		"200:1": 7,
	})

	store.CleanupProcess(100)

	if _, ok := store.paths["100:cwd"]; ok {
		t.Fatal("parent cwd entry was not removed")
	}
	if _, ok := store.paths["100:1"]; ok {
		t.Fatal("parent fd entry was not removed")
	}
	if _, ok := store.offsets["100:1"]; ok {
		t.Fatal("parent fd offset was not removed")
	}
	if got := store.paths["200:1"]; got != "/other" {
		t.Fatalf("unrelated fd target = %q, want /other", got)
	}
}
