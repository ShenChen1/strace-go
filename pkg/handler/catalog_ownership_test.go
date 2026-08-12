package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

type catalogPortTestStub struct{}

func (catalogPortTestStub) Format() string {
	return "raw"
}

func (catalogPortTestStub) Table(string) (meta.XlatTable, bool) {
	return meta.XlatTable{}, false
}

func (catalogPortTestStub) SyscallArgXlat(string, string) (string, bool) {
	return "", false
}

func (catalogPortTestStub) DecodeFlags(uint64, string) string {
	return "catalog-port"
}

func TestHandlerCatalogConsumersDoNotConstructFallbackCatalog(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	for _, name := range []string{"meta_context.go", "statmount_format.go"} {
		source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(source), "meta.NewCatalog(") {
			t.Fatalf("%s constructs a catalog outside session composition", name)
		}
	}
}

func TestCatalogForContextUsesOnlyInjectedCatalog(t *testing.T) {
	injected := meta.NewCatalog("raw")
	ctx := &Context{
		Meta: injected,
		Opts: &cli.Options{XlatFormat: "verbose"},
	}
	if got := catalogForContext(ctx); got != injected {
		t.Fatalf("catalogForContext() = %p, want injected catalog %p", got, injected)
	}
	if got := catalogForContext(&Context{Opts: &cli.Options{XlatFormat: "raw"}}); got != nil {
		t.Fatalf("catalogForContext() without Meta = %p, want nil", got)
	}
}

func TestCatalogPortCanBeInjectedWithoutConcreteCatalog(t *testing.T) {
	ctx := &Context{Meta: catalogPortTestStub{}}
	if got := decodeFlags(ctx, 1, "test"); got != "catalog-port" {
		t.Fatalf("decodeFlags() = %q, want catalog-port", got)
	}
	if got := xlatFormat(ctx); got != "raw" {
		t.Fatalf("xlatFormat() = %q, want raw", got)
	}
}

func TestContextMetadataUsesCatalogPort(t *testing.T) {
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
				if name.Name != "Meta" {
					continue
				}
				selector, ok := field.Type.(*ast.SelectorExpr)
				if ok {
					found = selector.Sel.Name == "CatalogPort"
				}
			}
		}
		return false
	})
	if !found {
		t.Fatal("handler Context must depend on CatalogPort")
	}
}
