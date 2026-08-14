package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFLinkCleanupPropagatesErrors(t *testing.T) {
	root := repoRootForTest(t)
	attachSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_attach.go"))
	runtimeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	checks := []struct {
		source   string
		required string
	}{
		{source: attachSource, required: "func closeTracepointLinksParallelWithDiagnostics("},
		{source: attachSource, required: "errors.Join"},
		{source: runtimeSource, required: "linkErr := closeTracepointLinksParallelWithDiagnostics(links, clock, observer)"},
		{source: runtimeSource, required: "return errors.Join(linkErr, closeNamedBPFResourcesParallel(namedResources, clock, observer))"},
	}
	for _, check := range checks {
		if !strings.Contains(check.source, check.required) {
			t.Fatalf("BPF link cleanup is missing error propagation %q", check.required)
		}
	}
}
