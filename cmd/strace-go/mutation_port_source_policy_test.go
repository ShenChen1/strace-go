package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductMutationComponentsKeepFDStateBehindPorts(t *testing.T) {
	for _, relative := range []string{
		"cmd/strace-go/syscall_event_context.go",
		"cmd/strace-go/syscall_handler_runner.go",
		"cmd/strace-go/syscall_exit_pipeline.go",
		"cmd/strace-go/lifecycle_event_handler.go",
	} {
		path := filepath.Join(repositoryRoot(t), relative)
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if hasConcretePointerType(file, "FDStateStore") {
			t.Fatalf("%s directly depends on concrete FDStateStore", relative)
		}
	}
}

func hasConcretePointerType(file *ast.File, typeName string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		star, ok := node.(*ast.StarExpr)
		if !ok {
			return true
		}
		name, ok := star.X.(*ast.Ident)
		if ok && name.Name == typeName {
			found = true
		}
		return true
	})
	return found
}

func TestFDStateStoreDoesNotOwnRuntimeService(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "cmd/strace-go/fd_state_store.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(source)
	for _, token := range []string{
		"handler.RuntimeServices",
		"func (st *FDStateStore) Runtime",
		"handler.NewRuntime()",
	} {
		if strings.Contains(text, token) {
			t.Fatalf("FDStateStore retains unrelated runtime ownership token %q", token)
		}
	}
}
