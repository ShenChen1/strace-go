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
		"runErr = joinTraceRunError(runErr, outputHandoff.Close())",
		"runErr = joinTraceRunError(runErr, targetHandoff.Close())",
		"runErr = joinTraceRunError(runErr, targetBootstrap.Close())",
		"runErr = joinTraceRunError(runErr, events.Close())",
		"runErr = joinTraceRunError(runErr, bpfRuntime.Close())",
		"joinTraceRunError(err, output.Close())",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("runTraceSession is missing cleanup error propagation %q", required)
		}
	}
}
