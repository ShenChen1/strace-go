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

func TestWriteGoSyscallTableReportsWriteError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}

	err := writeGoSyscallTable("/dev/full", map[int]SyscallMeta{
		1: {Name: "write", Args: []string{"fd"}, ArgTypes: []string{"int"}, Flags: "TD"},
	})
	if err == nil {
		t.Fatal("writeGoSyscallTable(/dev/full) error = nil, want write error")
	}
	if !strings.Contains(err.Error(), "write /dev/full") {
		t.Fatalf("writeGoSyscallTable(/dev/full) error = %v, want write context", err)
	}
}
