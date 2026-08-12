package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	defaultSyscallTableRelPath  = "pkg/meta/syscall_table.go"
	defaultRuntimeABIHeaderPath = "bpf/syscall_numbers_generated.h"
	generateSyscallsPackagePath = "cmd/generate-syscalls"
)

func resolveRepoPath(rel string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	root, err := findRepoRoot(wd)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, rel), nil
}

func findRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path for %q: %w", start, err)
	}
	for {
		if isFile(filepath.Join(dir, "go.mod")) && isDir(filepath.Join(dir, generateSyscallsPackagePath)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("find repo root from %q", start)
		}
		dir = parent
	}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
