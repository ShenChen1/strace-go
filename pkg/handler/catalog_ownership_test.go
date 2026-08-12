package handler

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

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
