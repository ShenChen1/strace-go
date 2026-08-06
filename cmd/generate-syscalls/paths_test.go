package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindRepoRootFromRootAndNestedDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/repo\n")
	nested := filepath.Join(root, generateSyscallsPackagePath, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}

	for _, start := range []string{root, nested} {
		got, err := findRepoRoot(start)
		if err != nil {
			t.Fatalf("findRepoRoot(%q) error = %v", start, err)
		}
		if got != root {
			t.Fatalf("findRepoRoot(%q) = %q, want %q", start, got, root)
		}
	}
}

func TestFindRepoRootReportsMissingMarkers(t *testing.T) {
	if _, err := findRepoRoot(t.TempDir()); err == nil {
		t.Fatal("findRepoRoot() error = nil, want missing marker error")
	}
}

func TestGeneratorCommandResolvesDefaultOutputPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/repo\n")
	if err := os.MkdirAll(filepath.Join(root, generateSyscallsPackagePath), 0o755); err != nil {
		t.Fatalf("create generator package marker: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(filepath.Join(root, generateSyscallsPackagePath)); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	got, err := (generatorCommand{}).outputPath("")
	if err != nil {
		t.Fatalf("outputPath(\"\") error = %v", err)
	}
	want := filepath.Join(root, defaultSyscallTableRelPath)
	if got != want {
		t.Fatalf("outputPath(\"\") = %q, want %q", got, want)
	}
}

func writeFile(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent for %q: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
