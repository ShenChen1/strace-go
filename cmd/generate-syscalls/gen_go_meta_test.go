package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGoSyscallTableDeterministic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscall_table.go")
	syscalls := map[int]SyscallMeta{
		2: {Name: "open", Args: []string{"filename"}, ArgTypes: []string{"const char *"}, Flags: "TF"},
		1: {Name: "write", Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "const char *"}, Flags: "TD"},
	}

	if err := writeGoSyscallTable(path, syscalls); err != nil {
		t.Fatalf("writeGoSyscallTable() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated table: %v", err)
	}
	got := string(data)
	first := strings.Index(got, `1: {Name: "write"`)
	second := strings.Index(got, `2: {Name: "open"`)
	if first < 0 || second < 0 || first > second {
		t.Fatalf("generated table order/content unexpected:\n%s", got)
	}
}
