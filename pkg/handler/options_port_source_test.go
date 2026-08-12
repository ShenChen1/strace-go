package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestContextOptionsUsesOptionsPort(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "handler.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse handler.go: %v", err)
	}
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Context" {
			return true
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if name.Name != "Opts" {
					continue
				}
				optionsType, ok := field.Type.(*ast.Ident)
				found = ok && optionsType.Name == "OptionsPort"
			}
		}
		return false
	})
	if !found {
		t.Fatal("handler Context must depend on OptionsPort")
	}
}

func TestProductionCodeUsesOptionsCapabilities(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(currentFile), "..", "..")
	pattern := regexp.MustCompile(`ctx\.Opts\.(Verbose|StringLimit|HexEscapeMode|VerboseDisabled|ShowPaths|ShowPathsMode|TraceReadFDs|TraceWriteFDs)([^A-Za-z0-9_]|$)`)
	for _, relativeRoot := range []string{"pkg/handler", "cmd/strace-go"} {
		root := filepath.Join(repoRoot, relativeRoot)
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if match := pattern.Find(data); match != nil {
				t.Errorf("%s uses concrete options field %q", path, match)
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
