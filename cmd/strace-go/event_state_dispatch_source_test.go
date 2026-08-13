package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceStateEntryDelegatesEventOwnership(t *testing.T) {
	root := repoRootForTest(t)
	stateSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state.go"))
	dispatchSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state_dispatch.go"))
	entry := sourceFunctionBody(t, dispatchSource, "func (st *TraceState) handleEnvelope")
	for _, required := range []string{
		"st.pendingForOtherTID(envelope.tid)",
		"st.handleLifecycleEnvelope(envelope, unfinished)",
		"st.handleSyscallEnvelope(envelope, unfinished)",
	} {
		if !strings.Contains(entry, required) {
			t.Fatalf("TraceState entry missing delegation %q", required)
		}
	}
	for _, forbidden := range []string{
		"st.applyLifecycleEvent(",
		"st.rememberEnterEvent(",
		"st.consumeEnterEvent(",
		"st.rememberExitFragment(",
		"st.retireTask(",
	} {
		if strings.Contains(entry, forbidden) {
			t.Fatalf("TraceState entry owns delegated mutation %q", forbidden)
		}
	}

	syscall := sourceFunctionBody(t, dispatchSource, "func (st *TraceState) handleSyscallEnvelope")
	for _, required := range []string{
		"st.handleSyscallEnter(",
		"st.handleSyscallFragment(",
		"st.handleSyscallExit(",
	} {
		if !strings.Contains(syscall, required) {
			t.Fatalf("syscall dispatcher missing responsibility %q", required)
		}
	}
	if strings.Contains(stateSource, "func (st *TraceState) handleEnvelope") {
		t.Fatal("TraceState entry must live in the dispatch file")
	}
}

func sourceFunctionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	if start < 0 {
		t.Fatalf("source missing function %q", signature)
	}
	end := strings.Index(source[start:], "\nfunc ")
	if end < 0 {
		return source[start:]
	}
	return source[start : start+end]
}
