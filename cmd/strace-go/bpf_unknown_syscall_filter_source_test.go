package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSyscallFilterPassesOnlyUnknownMapMisses(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/runtime_stats.h"))

	for _, contract := range []string{
		"if (!selected) {\n        return (*cfg & CONFIG_SYSCALL_FILTER_STRICT_UNKNOWN) ? 0 : 1;",
		"return *selected ? 0 : 1;",
		"return *selected ? 1 : 0;",
	} {
		if !strings.Contains(source, contract) {
			t.Fatalf("BPF syscall filter is missing unknown-ID contract %q", contract)
		}
	}
}
