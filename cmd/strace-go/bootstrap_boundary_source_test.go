package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapSideEffectsStayOutsideSessionRuntime(t *testing.T) {
	root := repoRootForTest(t)
	sessionPath := filepath.Join(root, "cmd/strace-go/session.go")
	if _, err := os.Stat(sessionPath); err == nil {
		t.Fatal("mixed session.go bootstrap file still exists")
	}

	runtimeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_runtime.go"))
	for _, forbidden := range []string{
		"traceBPFTargetPort",
		"exec.Command",
		"openFileDescriptors",
		"setupOutput",
	} {
		if strings.Contains(runtimeSource, forbidden) {
			t.Fatalf("session runtime still owns bootstrap detail %q", forbidden)
		}
	}

	targetSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/target_bootstrap.go"))
	outputSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/output_bootstrap.go"))
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	for _, required := range []string{
		"type traceTargetBootstrap struct",
		"func newTraceTargetBootstrap(",
		"func (b *traceTargetBootstrap) Resolve(",
		"func (b *traceTargetBootstrap) Close() error",
	} {
		if !strings.Contains(targetSource, required) {
			t.Fatalf("target bootstrap is missing %q", required)
		}
	}
	if !strings.Contains(outputSource, "func setupOutput(") {
		t.Fatal("output bootstrap does not own setupOutput")
	}
	for _, required := range []string{
		"newTraceTargetBootstrap(bpfRuntime)",
		"targetBootstrap.Resolve(config.targets)",
		"cleanup.Add(\"target_bootstrap\", targetBootstrap.Close)",
	} {
		if !strings.Contains(mainSource, required) {
			t.Fatalf("main is missing bootstrap composition step %q", required)
		}
	}
}
