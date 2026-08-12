package main

import (
	"path/filepath"
	"testing"
)

type recordingSyscallNumberHeaderWriter struct {
	path    string
	numbers []syscallNumberEntry
}

func (w *recordingSyscallNumberHeaderWriter) Write(path string, numbers []syscallNumberEntry) error {
	w.path = path
	w.numbers = numbers
	return nil
}

func TestGeneratorCommandWritesRuntimeABIHeader(t *testing.T) {
	writer := &recordingSyscallNumberHeaderWriter{}
	path := filepath.Join(t.TempDir(), "syscall_numbers_generated.h")
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{syscalls: map[int]SyscallMeta{
			39: {Name: "getpid"},
		}},
		writer:           &fakeSyscallTableWriter{},
		runtimeABIWriter: writer,
		runtimeABIPath:   path,
	}

	if err := cmd.Run(nil, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if writer.path != path {
		t.Fatalf("runtime header path = %q, want %q", writer.path, path)
	}
	if len(writer.numbers) == 0 {
		t.Fatal("runtime header writer received no syscall numbers")
	}
}
