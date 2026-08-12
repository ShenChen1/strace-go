package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceTargetCleanupUsesExplicitHandoff(t *testing.T) {
	root := repoRootForTest(t)
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))

	for _, forbidden := range []string{
		"cleanupTargets :=",
		"abortTraceTargets(",
	} {
		if strings.Contains(mainSource, forbidden) {
			t.Fatalf("main still owns target cleanup through %q", forbidden)
		}
	}
	handoffSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_handoff.go"))
	for _, required := range []string{
		"type traceTargetHandoff struct",
		"func newTraceTargetHandoff(",
		"func (h *traceTargetHandoff) Transfer() error",
		"func (h *traceTargetHandoff) Close() error",
	} {
		if !strings.Contains(handoffSource, required) {
			t.Fatalf("target handoff is missing %q", required)
		}
	}
}
