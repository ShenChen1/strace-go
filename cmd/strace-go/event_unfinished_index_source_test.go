package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUnfinishedCandidateIndexSourceContract(t *testing.T) {
	root := repositoryRoot(t)
	stateSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_unfinished_state.go"))
	state := stateSource + ownerSource
	if !strings.Contains(ownerSource, "type traceUnfinishedState struct") {
		t.Fatal("unfinished state owner is missing")
	}
	for _, forbidden := range []string{
		"\tunfinishedEnabled",
		"\tunqueuedUnfinished",
		"\tinFlightUnfinished",
		"\treusableUnfinished",
	} {
		if strings.Contains(stateSource, forbidden) {
			t.Fatalf("TraceState must not own unfinished field %q", forbidden)
		}
	}
	for _, snippet := range []string{
		"unqueued",
		"inFlight",
		"requeue(",
		"deleteCandidate(",
		"enabled",
		"setEnabled(",
		"unfinishedSyscallView",
		"unfinishedView()",
		"reusable",
		"acquireViews(",
	} {
		if !strings.Contains(ownerSource, snippet) {
			t.Fatalf("event state candidate index missing %q", snippet)
		}
	}
	if strings.Contains(state, "copyPendingSyscallState") {
		t.Fatal("unfinished candidate path must not deep-copy complete pending syscall state")
	}
	if !strings.Contains(ownerSource, "clear(views)") {
		t.Fatal("unfinished release must clear reusable view elements")
	}
	dispatcher := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_dispatcher.go"))
	router := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_router.go"))
	composition := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(dispatcher, "if d.pipeline == nil || !d.pipeline.HasTextOutput()") ||
		!strings.Contains(dispatcher, "markUnfinishedPrinted") {
		t.Fatal("event dispatcher must resolve unfinished candidates when no text pipeline exists")
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
