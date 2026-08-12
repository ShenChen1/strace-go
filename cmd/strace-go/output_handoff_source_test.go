package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTraceSessionTransfersOutputOwnership(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	if strings.Contains(source, "defer func() { _ = output.Close() }") {
		t.Fatal("runTraceSession still closes output independently of session ownership")
	}
	for _, required := range []string{
		"newTraceOutputHandoff(output)",
		"outputHandoff.Transfer()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("runTraceSession is missing output ownership step %q", required)
		}
	}
}

func TestOutputHandoffTypeExists(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/trace_output.go"))
	for _, required := range []string{
		"type traceOutputHandoff struct",
		"func newTraceOutputHandoff(",
		"func (h *traceOutputHandoff) Transfer()",
		"func (h *traceOutputHandoff) Close() error",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("trace output handoff is missing %q", required)
		}
	}
}
