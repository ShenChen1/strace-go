package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBPFCaptureHeaderDeterministic(t *testing.T) {
	oldConfig := globalConfig
	t.Cleanup(func() { globalConfig = oldConfig })
	globalConfig = Config{
		Rules: []CaptureRule{
			{
				Syscalls: []string{"write", "read"},
				Enter: CapturePoint{Reads: []CaptureRead{
					{Arg: 1, Size: 8, Type: "raw"},
				}},
			},
		},
	}

	path := filepath.Join(t.TempDir(), "syscall_capture.h")
	syscalls := map[int]SyscallMeta{
		2: {Name: "write"},
		1: {Name: "read"},
	}

	if err := writeBPFCaptureHeader(path, syscalls); err != nil {
		t.Fatalf("writeBPFCaptureHeader() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated header: %v", err)
	}
	got := string(data)
	first := strings.Index(got, "case 1: /* read */")
	second := strings.Index(got, "case 2: /* write */")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("generated header order/content unexpected:\n%s", got)
	}
}

func TestWriteBPFCaptureHeaderReportsWriteError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}

	err := writeBPFCaptureHeader("/dev/full", map[int]SyscallMeta{
		1: {Name: "read"},
	})
	if err == nil {
		t.Fatal("writeBPFCaptureHeader(/dev/full) error = nil, want write error")
	}
	if !strings.Contains(err.Error(), "write /dev/full") {
		t.Fatalf("writeBPFCaptureHeader(/dev/full) error = %v, want write context", err)
	}
}
