package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestProductEventRouterKeepsOutputBehindPorts(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "cmd/strace-go/event_router.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, typeName := range []string{"LifecycleEventHandler", "SyscallJSONOutput", "SyscallExitPipeline"} {
		if hasConcretePointerType(file, typeName) {
			t.Fatalf("event router directly depends on concrete %s", typeName)
		}
	}
}
