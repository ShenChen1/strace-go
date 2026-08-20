package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerContextPortsAreBoundOutsideEventConstruction(t *testing.T) {
	root := repositoryRoot(t)
	contextSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/syscall_event_context.go"))
	if strings.Contains(contextSource, "deps.contextPool.configureSessionPorts") {
		t.Fatal("event context construction must not configure session ports per event")
	}
	compositionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(compositionSource, "newHandlerContextRecyclerWithPorts") {
		t.Fatal("session composition must create a preconfigured handler context recycler")
	}
}
