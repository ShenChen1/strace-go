package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsesSessionAttachPolicy(t *testing.T) {
	root := repoRootForTest(t)
	runSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_run.go"))
	if strings.Contains(runSource, "deps.Opts") || strings.Contains(runSource, "attachPIDs(deps.Opts)") {
		t.Fatal("run must not read attach PIDs from cli.Options")
	}
	if !strings.Contains(runSource, "AttachPIDs()") {
		t.Fatal("run must consume the session attach policy")
	}
	compositionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if !strings.Contains(compositionSource, "AttachPIDs()") {
		t.Fatal("exit-status composition must consume the session attach policy")
	}
}
