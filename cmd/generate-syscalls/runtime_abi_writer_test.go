package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGeneratedSyscallNumberHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscall_numbers_generated.h")
	numbers := []syscallNumberEntry{
		{ID: 1, Name: "write"},
		{ID: 35, Name: "nanosleep"},
		{ID: 0, Name: "read"},
	}

	if err := (generatedSyscallNumberHeaderWriter{}).Write(path, numbers); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated header: %v", err)
	}
	got := string(data)
	for name := range runtimeABIVariableNames {
		macro := "#define SYS_" + strings.ToUpper(name) + " "
		if strings.Contains(got, macro) {
			t.Fatalf("generated header redefined BPF-managed volatile syscall %q", name)
		}
	}
	readIndex := strings.Index(got, "#define SYS_READ 0")
	writeIndex := strings.Index(got, "#define SYS_WRITE 1")
	if readIndex < 0 || writeIndex < 0 || readIndex > writeIndex {
		t.Fatalf("generated header order/content unexpected:\n%s", got)
	}
}

func TestWriteGeneratedSyscallNumberHeaderReportsWriteError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}

	err := (generatedSyscallNumberHeaderWriter{}).Write("/dev/full", []syscallNumberEntry{{ID: 0, Name: "read"}})
	if err == nil {
		t.Fatal("Write(/dev/full) error = nil, want write error")
	}
	if !strings.Contains(err.Error(), "write /dev/full") {
		t.Fatalf("Write(/dev/full) error = %v, want write context", err)
	}
}
