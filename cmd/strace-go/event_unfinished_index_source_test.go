package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUnfinishedCandidateIndexSourceContract(t *testing.T) {
	root := repositoryRoot(t)
	state := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state.go")) +
		readTextFile(t, filepath.Join(root, "cmd/strace-go/event_unfinished_state.go"))
	for _, snippet := range []string{
		"unqueuedUnfinished",
		"inFlightUnfinished",
		"requeueUnfinished",
		"deleteUnfinishedCandidate",
		"unfinishedEnabled",
		"setUnfinishedEnabled",
	} {
		if !strings.Contains(state, snippet) {
			t.Fatalf("event state candidate index missing %q", snippet)
		}
	}
	router := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_router.go"))
	if !strings.Contains(router, "if r.pipeline == nil || !r.pipeline.HasTextOutput()") ||
		!strings.Contains(router, "markUnfinishedPrinted") {
		t.Fatal("router must resolve unfinished candidates when no text pipeline exists")
	}
	if !strings.Contains(router, "state.setUnfinishedEnabled(deps.Pipeline != nil && deps.Pipeline.HasTextOutput())") {
		t.Fatal("router must configure unfinished capability from the text output port")
	}
}
