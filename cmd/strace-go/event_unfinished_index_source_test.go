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
		"reusableUnfinished",
		"acquireUnfinishedViews",
	} {
		if !strings.Contains(state, snippet) {
			t.Fatalf("event state candidate index missing %q", snippet)
		}
	}
	if strings.Contains(state, "copyPendingSyscallState") {
		t.Fatal("unfinished candidate path must not deep-copy complete pending syscall state")
	}
	if !strings.Contains(state, "clear(update.unfinished)") {
		t.Fatal("unfinished release must clear reusable view elements")
	}
	router := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_router.go"))
	composition := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(router, "if r.pipeline == nil || !r.pipeline.HasTextOutput()") ||
		!strings.Contains(router, "markUnfinishedPrinted") {
		t.Fatal("router must resolve unfinished candidates when no text pipeline exists")
	}
	if strings.Contains(router, "setUnfinishedEnabled") {
		t.Fatal("router must not configure event state during construction")
	}
	if !strings.Contains(composition, "deps.State.setUnfinishedEnabled(outputs.syscallText.textMode())") {
		t.Fatal("composition root must configure unfinished capability from text mode")
	}
	if strings.Contains(router, "[]pendingSyscallState") || strings.Contains(router, "*pendingSyscallState") {
		t.Fatal("router must consume immutable unfinished views instead of mutable pending state")
	}
	if strings.Contains(state, "pendingEnter    *pendingSyscallState") ||
		!strings.Contains(state, "pendingEnter    *pendingSyscallSnapshot") {
		t.Fatal("state updates must expose pending syscall snapshots, not mutable owners")
	}
}
