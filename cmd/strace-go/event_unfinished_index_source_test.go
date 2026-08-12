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
		"unfinishedSyscallView",
		"unfinishedView()",
	} {
		if !strings.Contains(state, snippet) {
			t.Fatalf("event state candidate index missing %q", snippet)
		}
	}
	if strings.Contains(state, "copyPendingSyscallState") {
		t.Fatal("unfinished candidate path must not deep-copy complete pending syscall state")
	}
	router := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_router.go"))
	if !strings.Contains(router, "if r.pipeline == nil || !r.pipeline.HasTextOutput()") ||
		!strings.Contains(router, "markUnfinishedPrinted") {
		t.Fatal("router must resolve unfinished candidates when no text pipeline exists")
	}
	if !strings.Contains(router, "state.setUnfinishedEnabled(deps.Pipeline != nil && deps.Pipeline.HasTextOutput())") {
		t.Fatal("router must configure unfinished capability from the text output port")
	}
	if strings.Contains(router, "[]pendingSyscallState") || strings.Contains(router, "*pendingSyscallState") {
		t.Fatal("router must consume immutable unfinished views instead of mutable pending state")
	}
}
