package main

import (
	"os"
	"testing"
)

func TestInheritProcessStateCopiesFDAndCWD(t *testing.T) {
	session := &traceSession{
		fdMap: map[string]string{
			"100:cwd": "/tmp",
			"100:1":   "/tmp/out",
			"200:1":   "/other",
		},
		fdOffsets: map[string]int64{
			"100:1": 42,
			"200:1": 7,
		},
		fdFiles: make(map[string]*os.File),
	}

	session.inheritProcessState(100, 101)

	if got := session.fdMap["101:cwd"]; got != "/tmp" {
		t.Fatalf("child cwd = %q, want /tmp", got)
	}
	if got := session.fdMap["101:1"]; got != "/tmp/out" {
		t.Fatalf("child fd target = %q, want /tmp/out", got)
	}
	if got := session.fdOffsets["101:1"]; got != 42 {
		t.Fatalf("child fd offset = %d, want 42", got)
	}
	if got := session.fdMap["200:1"]; got != "/other" {
		t.Fatalf("unrelated fd target = %q, want /other", got)
	}
}

func TestCleanupProcessStateRemovesFDState(t *testing.T) {
	session := &traceSession{
		fdMap: map[string]string{
			"100:cwd": "/tmp",
			"100:1":   "/tmp/out",
			"200:1":   "/other",
		},
		fdOffsets: map[string]int64{
			"100:1": 42,
			"200:1": 7,
		},
		fdFiles: make(map[string]*os.File),
	}

	session.cleanupProcessState(100)

	if _, ok := session.fdMap["100:cwd"]; ok {
		t.Fatal("parent cwd entry was not removed")
	}
	if _, ok := session.fdMap["100:1"]; ok {
		t.Fatal("parent fd entry was not removed")
	}
	if _, ok := session.fdOffsets["100:1"]; ok {
		t.Fatal("parent fd offset was not removed")
	}
	if got := session.fdMap["200:1"]; got != "/other" {
		t.Fatalf("unrelated fd target = %q, want /other", got)
	}
}
