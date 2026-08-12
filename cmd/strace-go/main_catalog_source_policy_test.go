package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMainCatalogCompositionUsesCLIFormat(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	for _, forbidden := range []string{
		"metaCatalogForOptions(",
		"meta.NewCatalog(\"abbrev\")",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("main catalog source contains implicit policy %q", forbidden)
		}
	}
	if !strings.Contains(source, "Catalog:       meta.NewCatalog(opts.XlatFormat)") {
		t.Fatal("main composition must create catalog from CLI XlatFormat")
	}
}
