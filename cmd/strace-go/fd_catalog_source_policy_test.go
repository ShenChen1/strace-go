package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFDStateUsesFlagDecoderPort(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	fdStateSource := readTextFile(t, filepath.Join(root, "fd_state_store.go"))
	if !strings.Contains(fdStateSource, "type fdFlagDecoder interface") {
		t.Fatal("fd state must define a narrow flag decoder port")
	}
	if !strings.Contains(fdStateSource, "flagDecoder fdFlagDecoder") {
		t.Fatal("fd state update must name the injected flag decoder")
	}

	concreteCatalog := regexp.MustCompile(`catalog\s+\*meta\.Catalog`)
	for _, name := range []string{"event_utils.go", "fd_state_store.go", "syscall_event_context.go"} {
		source := readTextFile(t, filepath.Join(root, name))
		if match := concreteCatalog.FindString(source); match != "" {
			t.Fatalf("%s exposes concrete catalog in FD state path: %q", name, match)
		}
	}
}
