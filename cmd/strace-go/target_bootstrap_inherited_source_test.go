package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInheritedFDCollectorErrorBoundarySource(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/target_bootstrap.go"))
	for _, required := range []string{
		"inheritedFiles, err := collectInheritedFiles()",
		"return nil, fmt.Errorf(\"collect inherited files: %w\", err)",
		"func collectInheritedFiles() ([]*os.File, error)",
		"func collectInheritedFilesFromFDs(fds []int, duplicate inheritedFileDuplicator) ([]*os.File, error)",
		"if errors.Is(err, unix.EBADF)",
		"return nil, fmt.Errorf(\"check inherited file descriptor %d: %w\", fd, err)",
		"errors.Join(",
		"closeFiles(files)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("target bootstrap source missing %q", required)
		}
	}
}
