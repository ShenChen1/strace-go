package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionComponentsAreNotLazyBuilt(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		source := readTextFile(t, filepath.Join(root, file.Name()))
		if strings.Contains(source, "componentsOrBuild") {
			t.Fatalf("production file %s still owns lazy component construction", file.Name())
		}
	}
}
