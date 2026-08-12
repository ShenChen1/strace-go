package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOutputBootstrapPropagatesSetupCleanupErrors(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/output_bootstrap.go"))
	for _, required := range []string{
		"func cleanupOutputBootstrap(writer io.Closer, command traceOutputWaiter) error",
		"func closeOutputFile(path string, file *os.File) error",
		"errors.Join(err, cleanupOutputBootstrap(stdin, nil))",
		"errors.Join(err, cleanupOutputBootstrap(stdin, execTraceOutputWaiter{command: cmd}))",
		"errors.Join(err, closeOutputFile(outFileOpt, outFile))",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("output bootstrap is missing cleanup error propagation %q", required)
		}
	}
}
