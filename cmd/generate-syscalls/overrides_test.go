package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestManualOverridesAreNotMutatedByInit(t *testing.T) {
	mutation := regexp.MustCompile(`manualOverrides\[[^\]]+\]\s*=`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read generator dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if mutation.Match(data) {
			t.Fatalf("%s mutates manualOverrides; keep overrides explicit in overrides.go", name)
		}
	}
}

func TestManualOverridesHaveConsistentShape(t *testing.T) {
	for key, meta := range manualOverrides {
		if meta.Name != key {
			t.Fatalf("manualOverrides[%q].Name = %q, want %q", key, meta.Name, key)
		}
		if len(meta.Args) != len(meta.ArgTypes) {
			t.Fatalf("manualOverrides[%q] has %d args and %d arg types", key, len(meta.Args), len(meta.ArgTypes))
		}
		for i := range meta.Args {
			if meta.Args[i] == "" {
				t.Fatalf("manualOverrides[%q].Args[%d] is empty", key, i)
			}
			if meta.ArgTypes[i] == "" {
				t.Fatalf("manualOverrides[%q].ArgTypes[%d] is empty", key, i)
			}
		}
	}
}
