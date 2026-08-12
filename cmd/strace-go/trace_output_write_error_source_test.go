package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceOutputWriteErrorBoundarySource(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/trace_output.go"))
	for _, required := range []string{
		"writeErr error",
		"if err == nil && n != len(p)",
		"o.writeErr = fmt.Errorf(\"write trace output: %w\", err)",
		"closeErr := o.writeErr",
		"closeErr = errors.Join(closeErr, o.closer.Close())",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("trace output source missing %q", required)
		}
	}
}
