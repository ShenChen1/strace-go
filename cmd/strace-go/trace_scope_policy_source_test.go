package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceScopeUsesSessionPolicyPort(t *testing.T) {
	root := repoRootForTest(t)
	scopeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_scope.go"))
	if strings.Contains(scopeSource, "*cli.Options") {
		t.Fatal("TraceScope must not depend on cli.Options")
	}
	if !strings.Contains(scopeSource, "type traceScopePolicy interface") {
		t.Fatal("TraceScope policy port is missing")
	}
	compositionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(compositionSource, "newTraceScope(deps.TargetPID, base.outputPolicy)") {
		t.Fatal("session composition must inject the shared output policy into TraceScope")
	}
}
