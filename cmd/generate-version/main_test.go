package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMetadataRendersCheckedInFile(t *testing.T) {
	root, err := findVersionRepoRoot()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	metadata, err := loadVersionMetadata(root)
	if err != nil {
		t.Fatalf("load version metadata: %v", err)
	}
	source, err := renderVersionMetadata(metadata)
	if err != nil {
		t.Fatalf("render version metadata: %v", err)
	}
	if err := checkVersionFile(filepath.Join(root, defaultVersionOutputPath), source); err != nil {
		t.Fatal(err)
	}
}

func TestCIWorkflowFetchesHistoryForVersionMetadata(t *testing.T) {
	root, err := findVersionRepoRoot()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "architecture.yml"))
	if err != nil {
		t.Fatalf("read architecture workflow: %v", err)
	}
	workflow := string(data)
	checkoutCount := strings.Count(workflow, "uses: actions/checkout@v4")
	fetchAllCount := strings.Count(workflow, "fetch-depth: 0")
	if checkoutCount == 0 || fetchAllCount != checkoutCount {
		t.Fatalf("architecture workflow checkout blocks=%d fetch-depth: 0=%d", checkoutCount, fetchAllCount)
	}
}

func TestVersionMetadataValidationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		metadata versionMetadata
		want     string
	}{
		{name: "empty version", metadata: versionMetadata{year: "2026"}, want: "invalid upstream version"},
		{name: "version newline", metadata: versionMetadata{version: "7.1\nunsafe", year: "2026"}, want: "invalid upstream version"},
		{name: "invalid year", metadata: versionMetadata{version: "7.1", year: "26"}, want: "invalid upstream copyright year"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateVersionMetadata(test.metadata)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWriteVersionFileReportsFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full is unavailable")
	}
	if err := writeVersionFile("/dev/full", "version"); err == nil {
		t.Fatal("writeVersionFile succeeded on /dev/full")
	}
}
