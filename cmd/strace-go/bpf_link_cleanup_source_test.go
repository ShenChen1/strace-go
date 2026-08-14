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
		{source: attachSource, required: "func closeTracepointLinks(links []link.Link) error"},
		{source: attachSource, required: "errors.Join"},
		{source: runtimeSource, required: "linkErr := closeTracepointLinks(links)"},
		{source: runtimeSource, required: "return errors.Join(linkErr, handlerErr, objects.Close(), closeBPFExtraResources(extraClosers))"},
	}
	for _, check := range checks {
		if !strings.Contains(check.source, check.required) {
			t.Fatalf("BPF link cleanup is missing error propagation %q", check.required)
		}
	}
}
