package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedMetadataConsistency(t *testing.T) {
	if err := generateTargetMetadata("all", "", true); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedMetadataCheckRejectsDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table.go")
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeGeneratedOutput(path, []byte("expected"), true); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("check = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "stale" {
		t.Fatal("check changed the file")
	}
}
