package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceStateProductionSourceHasNoFixtureConstructors(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/event_state.go"))
	for _, forbidden := range []string{
		"func newTraceState()",
		"func newTraceStateWithDeferredExit(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("production state source contains test fixture constructor %q", forbidden)
		}
	}
}

func TestTraceStateFixtureConstructorsKeepDefaults(t *testing.T) {
	state := newTraceState()
	if !state.lifecycle.trackForkIdentity || !state.unfinished.enabled {
		t.Fatalf("test state defaults = %+v, want fork identity and unfinished enabled", state)
	}

	deferred := newTraceStateWithDeferredExit(true)
	if !deferred.deferUnmatchedExits || !deferred.lifecycle.trackForkIdentity || !deferred.unfinished.enabled {
		t.Fatalf("deferred state defaults = %+v, want all policy flags enabled", deferred)
	}
}
