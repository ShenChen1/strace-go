package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeparateTraceOutputRoutesAndClosesPIDFiles(t *testing.T) {
	base := filepath.Join(t.TempDir(), "trace")
	output, err := setupSeparateOutput(base, false)
	if err != nil {
		t.Fatalf("setupSeparateOutput() error = %v", err)
	}
	if err := output.SelectPID(101); err != nil {
		t.Fatalf("SelectPID(101) error = %v", err)
	}
	_, _ = output.Write([]byte("first\n"))
	if err := output.SelectPID(202); err != nil {
		t.Fatalf("SelectPID(202) error = %v", err)
	}
	_, _ = output.Write([]byte("second\n"))
	if err := output.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for pid, want := range map[string]string{"101": "first\n", "202": "second\n"} {
		data, err := os.ReadFile(base + "." + pid)
		if err != nil || string(data) != want {
			t.Fatalf("trace.%s = %q, err=%v, want %q", pid, data, err, want)
		}
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("base output exists, stat error = %v", err)
	}
}

func TestSeparateTraceOutputRejectsWriteBeforePIDSelection(t *testing.T) {
	output, err := setupSeparateOutput(filepath.Join(t.TempDir(), "trace"), false)
	if err != nil {
		t.Fatalf("setupSeparateOutput() error = %v", err)
	}
	if _, err := output.Write([]byte("unowned")); err == nil {
		t.Fatal("Write() before SelectPID returned nil error")
	}
	_ = output.Close()
}
