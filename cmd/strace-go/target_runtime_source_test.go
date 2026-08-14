package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceeWaitOwnershipIsCentralizedInTargetRuntime(t *testing.T) {
	root := repoRootForTest(t)
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	runSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_run.go"))
	compositionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	runtimeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_runtime.go"))

	for _, forbidden := range []string{
		"_ = cmd.Wait()",
		"w.command.Wait()",
	} {
		if strings.Contains(mainSource, forbidden) || strings.Contains(runSource, forbidden) {
			t.Fatalf("tracee Wait remains outside target runtime: %q", forbidden)
		}
	}
	for _, required := range []string{
		"type traceTargetRuntime struct",
		"func newTraceTargetRuntime(",
		"func (r *traceTargetRuntime) Abort()",
	} {
		if !strings.Contains(runtimeSource, required) {
			t.Fatalf("target runtime is missing %q", required)
		}
	}
	for _, required := range []string{
		"command:          deps.CommandWaiter",
		"commandWaiter: targetRuntime.commandWaiter()",
		"HasCommand:    bootstrap.hasCommand",
	} {
		if !strings.Contains(runSource+mainSource+compositionSource, required) {
			t.Fatalf("tracee completion wiring is missing %q", required)
		}
	}
}
