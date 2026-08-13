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
		t.Fatal("run state without clock or attach state must remain inert")
	}
}

func TestTraceRunStateUsesEventSourcedAttachLifecycle(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_run.go"))
	for _, required := range []string{
		"type traceAttachStateReader interface",
		"AttachTargetsDone() bool",
		"attachState traceAttachStateReader",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("run state is missing event-sourced attach contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"syscall.Kill(",
		"AnyAlive(",
		"systemTracePIDProbe",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("run state still probes attach liveness with %q", forbidden)
		}
	}
}
