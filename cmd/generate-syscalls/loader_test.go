package main

import (
	"errors"
	"reflect"
	"testing"
)

type fakeBTFSource struct {
	syscalls    map[string]SyscallMeta
	diagnostics map[string]btfSyscallDiagnostic
	err         error
	diagErr     error
}

func (s fakeBTFSource) LoadBTFSyscalls() (map[string]SyscallMeta, error) {
	return s.syscalls, s.err
}

func (s fakeBTFSource) LoadBTFSyscallDiagnostics() (map[string]btfSyscallDiagnostic, error) {
	return s.diagnostics, s.diagErr
}

type fakeEntrySource struct {
	entries []syscallentEntry
	err     error
}

func (s fakeEntrySource) LoadSyscallEntries() ([]syscallentEntry, error) {
	return s.entries, s.err
}

type fakeBTFDatasetSource struct {
	fakeBTFSource
	dataset      btfSyscallDataset
	datasetErr   error
	datasetCalls int
}

func (s *fakeBTFDatasetSource) LoadBTFSyscallDataset() (btfSyscallDataset, error) {
	s.datasetCalls++
	return s.dataset, s.datasetErr
}

func TestSyscallMetadataLoaderAppliesPriorityOrder(t *testing.T) {
	loader := syscallMetadataLoader{
		btfSource: fakeBTFSource{syscalls: map[string]SyscallMeta{
			"read":    {Name: "read", Args: []string{"btf_fd"}, ArgTypes: []string{"unsigned int"}},
			"newstat": {Name: "newstat", Args: []string{"path", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},
		}},
		entrySource: fakeEntrySource{entries: []syscallentEntry{
			{ID: 1, Name: "read", Argc: 3, Flags: "TD"},
			{ID: 2, Name: "stat", Argc: 2, Flags: "TF"},
			{ID: 3, Name: "missing", Argc: 2, Flags: "0"},
		}},
		overrides: map[string]SyscallMeta{
			"read": {Name: "read", Args: []string{"override_fd"}, ArgTypes: []string{"int"}},
		},
		aliases: map[string]string{"newstat": "stat"},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertMeta(t, got[1], SyscallMeta{Name: "read", Args: []string{"override_fd"}, ArgTypes: []string{"int"}, Flags: "TD"})
	assertMeta(t, got[2], SyscallMeta{Name: "stat", Args: []string{"path", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}, Flags: "TF"})
	assertMeta(t, got[3], SyscallMeta{Name: "missing", Args: []string{"arg0", "arg1"}, ArgTypes: []string{"unsigned long", "unsigned long"}, Flags: "0"})
}

func TestSyscallMetadataLoaderReportsSourceErrors(t *testing.T) {
	btfErr := errors.New("btf failed")
	if _, err := (syscallMetadataLoader{btfSource: fakeBTFSource{err: btfErr}}).Load(); !errors.Is(err, btfErr) {
		t.Fatalf("Load() BTF error = %v, want %v", err, btfErr)
	}

	entryErr := errors.New("entries failed")
	loader := syscallMetadataLoader{
		btfSource:   fakeBTFSource{syscalls: map[string]SyscallMeta{}},
		entrySource: fakeEntrySource{err: entryErr},
	}
	if _, err := loader.Load(); !errors.Is(err, entryErr) {
		t.Fatalf("Load() entry error = %v, want %v", err, entryErr)
	}
}

func TestDefaultLoaderUsesSyscallentPath(t *testing.T) {
	if defaultSyscallentRelPath != "strace-upstream/src/linux/x86_64/syscallent.h" {
		t.Fatalf("defaultSyscallentRelPath = %q", defaultSyscallentRelPath)
	}
}

func assertMeta(t *testing.T, got SyscallMeta, want SyscallMeta) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("meta = %#v, want %#v", got, want)
	}
}
