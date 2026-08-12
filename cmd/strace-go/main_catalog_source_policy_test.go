package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMainCatalogCompositionUsesCLIFormat(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_config.go"))
	for _, forbidden := range []string{
		"metaCatalogForOptions(",
		"meta.NewCatalog(\"abbrev\")",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("main catalog source contains implicit policy %q", forbidden)
		}
	}
	if !strings.Contains(source, "catalog:      meta.NewCatalog(opts.XlatFormat)") {
		t.Fatal("session config must create catalog from CLI XlatFormat")
	}
}
