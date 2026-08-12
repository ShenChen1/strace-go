package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFRuntimeOwnerKeepsGeneratedResourcesOutOfOrchestrators(t *testing.T) {
	root := repoRootForTest(t)
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	sessionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_runtime.go"))
	for file, source := range map[string]string{
		"main.go":            mainSource,
		"session_runtime.go": sessionSource,
	} {
		for _, forbidden := range []string{
			"*bpfObjects",
			"[]link.Link",
			"ringbuf.NewReader",
			"ConfigMap.Update",
			"closeTracepointLinks",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s still owns generated BPF resource %q", file, forbidden)
			}
		}
	}

	ownerSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	for _, required := range []string{
		"type traceBPFRuntime struct",
		"func setupBPF() (*traceBPFRuntime, error)",
		"func (r *traceBPFRuntime) newEventReader()",
		"func (r *traceBPFRuntime) configure(",
		"func (r *traceBPFRuntime) Close() error",
	} {
		if !strings.Contains(ownerSource, required) {
			t.Fatalf("BPF runtime owner is missing %q", required)
		}
	}
}
