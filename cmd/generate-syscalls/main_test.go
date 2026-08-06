package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeSyscallMapLoader struct {
	syscalls map[int]SyscallMeta
	err      error
}

func (l fakeSyscallMapLoader) Load() (map[int]SyscallMeta, error) {
	return l.syscalls, l.err
}

type fakeSyscallTableWriter struct {
	path     string
	syscalls map[int]SyscallMeta
	err      error
}

func (w *fakeSyscallTableWriter) Write(path string, syscalls map[int]SyscallMeta) error {
	w.path = path
	w.syscalls = syscalls
	return w.err
}

func TestRunGenerateSyscallsWritesConfiguredOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscall_table.go")
	writer := &fakeSyscallTableWriter{}
	syscalls := map[int]SyscallMeta{
		1: {Name: "write", Args: []string{"fd"}, ArgTypes: []string{"int"}, Flags: "TD"},
	}
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{syscalls: syscalls},
		writer: writer,
	}
	if err := cmd.Run([]string{"--output", path}, &bytes.Buffer{}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if writer.path != path {
		t.Fatalf("writer path = %q, want %q", writer.path, path)
	}
	if !reflect.DeepEqual(writer.syscalls, syscalls) {
		t.Fatalf("writer syscalls = %#v, want %#v", writer.syscalls, syscalls)
	}
}

func TestRunGenerateSyscallsWritesDefaultOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscall_table.go")
	writer := &fakeSyscallTableWriter{}
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{syscalls: map[int]SyscallMeta{
			39: {Name: "getpid", Flags: "0"},
		}},
		writer:            writer,
		defaultOutputPath: path,
	}
	if err := cmd.Run(nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if writer.path != path {
		t.Fatalf("writer path = %q, want %q", writer.path, path)
	}
}

func TestRunGenerateSyscallsReportsLoaderError(t *testing.T) {
	cmd := generatorCommand{loader: fakeSyscallMapLoader{err: errors.New("boom")}}
	err := cmd.Run([]string{"--output", filepath.Join(t.TempDir(), "syscall_table.go")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "load syscalls") {
		t.Fatalf("Run() error = %v, want load context", err)
	}
}

func TestRunGenerateSyscallsReportsWriterError(t *testing.T) {
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{syscalls: map[int]SyscallMeta{
			39: {Name: "getpid", Flags: "0"},
		}},
		writer: &fakeSyscallTableWriter{err: errors.New("disk full")},
	}
	err := cmd.Run([]string{"--output", filepath.Join(t.TempDir(), "syscall_table.go")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "write syscall table") {
		t.Fatalf("Run() error = %v, want write context", err)
	}
}

func TestRunGenerateSyscallsAuditOverrides(t *testing.T) {
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{err: errors.New("loader should not run")},
		auditSource: fakeBTFSource{syscalls: map[string]SyscallMeta{
			"read": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		}},
		overrides: map[string]SyscallMeta{
			"read": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		},
	}
	var out bytes.Buffer
	if err := cmd.Run([]string{"--audit-overrides"}, &out); err != nil {
		t.Fatalf("Run(--audit-overrides) error = %v", err)
	}
	if got, want := out.String(), "read\n"; got != want {
		t.Fatalf("Run(--audit-overrides) output = %q, want %q", got, want)
	}
}

func TestRunGenerateSyscallsAuditOverrideDetails(t *testing.T) {
	cmd := generatorCommand{
		loader: fakeSyscallMapLoader{err: errors.New("loader should not run")},
		auditSource: fakeBTFSource{syscalls: map[string]SyscallMeta{
			"read": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		}},
		overrides: map[string]SyscallMeta{
			"read": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		},
	}
	var out bytes.Buffer
	if err := cmd.Run([]string{"--audit-overrides-detail"}, &out); err != nil {
		t.Fatalf("Run(--audit-overrides-detail) error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "read\tredundant\texact_signature") {
		t.Fatalf("Run(--audit-overrides-detail) output = %q, want read detail row", got)
	}
}

func TestRunGenerateSyscallsRejectsUnknownFlag(t *testing.T) {
	cmd := generatorCommand{loader: fakeSyscallMapLoader{}}
	if err := cmd.Run([]string{"--unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("Run() error = nil, want flag error")
	}
}
