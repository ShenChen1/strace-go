package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEventContextUsesImmutableSessionPolicy(t *testing.T) {
	root := repoRootForTest(t)
	filterSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_filter.go"))
	if strings.Contains(filterSource, "opts       *cli.Options") {
		t.Fatal("trace filter must not retain cli.Options")
	}
	contextSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/syscall_event_context.go"))
	if strings.Contains(contextSource, "handlerOpts: deps.Opts") || strings.Contains(contextSource, "newTraceFilterOptions(deps.Opts)") {
		t.Fatal("event context must consume session policy ports")
	}
	policySource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_policy.go"))
	if !strings.Contains(policySource, "type cliTraceEventPolicy struct") {
		t.Fatal("event policy owner is missing")
	}
	compositionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(compositionSource, "EventPolicy:   config.eventPolicy") {
		t.Fatal("session composition must inject the event policy snapshot")
	}
}
