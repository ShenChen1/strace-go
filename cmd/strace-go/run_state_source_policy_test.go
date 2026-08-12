package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceRunStateDoesNotConstructDefaultPorts(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_run.go"))
	for _, forbidden := range []string{
		"clock = systemTraceClock{}",
		"pidProbe = systemTracePIDProbe{}",
		"pidProbeOrDefault",
		"return systemTraceClock{}.Now()",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("run state source contains implicit default port %q", forbidden)
		}
	}
}

func TestTraceRunStateWithoutPortsIsInert(t *testing.T) {
	state := newTraceRunState(traceRunStateDeps{attachPids: []int{101}})
	state.collect(nil)

	if state.attachExited {
		t.Fatal("run state without clock or PID probe must not poll attach liveness")
	}
	if !state.nextAttachPoll.IsZero() {
		t.Fatalf("run state without ports scheduled a poll: %s", state.nextAttachPoll)
	}
}
