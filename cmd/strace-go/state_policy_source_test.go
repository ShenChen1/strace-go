package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceStateUsesEventPolicyPort(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	start := strings.Index(source, "func newTraceStateForSession")
	if start < 0 {
		t.Fatal("newTraceStateForSession definition not found")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("newTraceStateForSession body not found")
	}
	body := source[start : start+end]
	if strings.Contains(body, "*cli.Options") {
		t.Fatal("TraceState construction must not depend on cli.Options")
	}
	if !strings.Contains(body, "ShouldDeferUnmatchedExits") || !strings.Contains(body, "TrackForkIdentity") {
		t.Fatal("TraceState construction must consume state policy ports")
	}
	policySource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_policy.go"))
	if !strings.Contains(policySource, "type traceStatePolicy interface") {
		t.Fatal("trace state policy port is missing")
	}
	if !strings.Contains(policySource, "var _ traceStatePolicy = (*cliTraceEventPolicy)(nil)") {
		t.Fatal("event policy does not implement trace state policy")
	}
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	if !strings.Contains(mainSource, "EventPolicy:   eventPolicy") {
		t.Fatal("session composition must pass the event policy snapshot")
	}
}
