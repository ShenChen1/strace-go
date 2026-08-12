package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetBootstrapCwdBoundarySource(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/target_bootstrap.go"))
	for _, required := range []string{
		"type traceWorkingDirectoryReader func() (string, error)",
		"func readInitialTraceCwd(reader traceWorkingDirectoryReader) (string, error)",
		"return readInitialTraceCwd(reader)",
		"initialCwd, err := b.readWorkingDirectory()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("target bootstrap source missing %q", required)
		}
	}
	readCwd := strings.Index(source, "initialCwd, err := b.readWorkingDirectory()")
	armFork := strings.Index(source, "if err := b.armNextFork(); err != nil")
	if readCwd < 0 || armFork < 0 || readCwd > armFork {
		t.Fatalf("cwd read must precede BPF arm: read=%d arm=%d", readCwd, armFork)
	}
}
