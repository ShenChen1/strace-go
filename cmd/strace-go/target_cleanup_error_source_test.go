package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetCleanupExposesResourceErrors(t *testing.T) {
	root := repoRootForTest(t)
	bpfSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	targetSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_bootstrap.go"))
	runtimeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_runtime.go"))
	handoffSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_handoff.go"))
	checks := []struct {
		source   string
		required string
	}{
		{source: bpfSource, required: "deleteFilterPID(pid uint32) error"},
		{source: targetSource, required: "func clearFilterPids(bpfRuntime traceBPFTargetPort, pids []uint32) error"},
		{source: targetSource, required: "func closeFiles(files []*os.File) error"},
		{source: runtimeSource, required: "func (r *traceTargetRuntime) Abort() error"},
		{source: handoffSource, required: "return errors.Join"},
	}
	for _, check := range checks {
		if !strings.Contains(check.source, check.required) {
			t.Fatalf("target cleanup is missing explicit error boundary %q", check.required)
		}
	}
}
