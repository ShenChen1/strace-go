package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTraceSessionPropagatesCleanupErrors(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	for _, required := range []string{
		"func runTraceSession(config *traceLaunchConfig, clock traceClock) (runErr error)",
		"func joinTraceRunError(primary error, cleanup error) error",
		"return errors.Join(primary, cleanup)",
		"defer func() { runErr = joinTraceRunError(runErr, cleanup.Close()) }()",
		"cleanup.Add(\"output\", outputHandoff.Close)",
		"cleanup.Add(\"target_handoff\", targetHandoff.Close)",
		"cleanup.Add(\"target_bootstrap\", targetBootstrap.Close)",
		"cleanup.Add(\"ringbuf_reader\", events.Close)",
		"return bpfRuntime.closeWithDiagnostics(clock, cleanupObserver)",
		"joinTraceRunError(err, output.Close())",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("runTraceSession is missing cleanup error propagation %q", required)
		}
	}
}
