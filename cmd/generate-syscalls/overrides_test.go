package main

import (
	"os"
	"strings"
	"testing"
)

func TestProductSourceHasNoFallbackResolver(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read generator directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, token := range []string{"fallbackOverrides", "metadataSourceFallbackOverride"} {
			if strings.Contains(string(data), token) {
				t.Errorf("%s contains removed fallback resolver token %q", name, token)
			}
		}
	}
}
