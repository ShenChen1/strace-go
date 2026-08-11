package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductRouterDoesNotMutateTraceStateSnapshots(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "cmd/strace-go/event_router.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.Contains(string(source), "unfinishedPrinted") {
		t.Fatal("event router directly mutates TraceState unfinished marker")
	}
}
