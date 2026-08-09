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
			"read": {Name: "read", Args: []string{"btf_fd"}, ArgTypes: []string{"unsigned int"}},
		}},
		tracepointSource: fakeTracepointSyscallSource{syscalls: map[string]SyscallMeta{
			"close": {Name: "close", Args: []string{"tracepoint_fd"}, ArgTypes: []string{"unsigned int"}},
		}},
		entrySource: fakeEntrySource{entries: []syscallentEntry{
			{ID: 1, Name: "read", Argc: 1, Flags: "TD"},
			{ID: 2, Name: "stat", Argc: 2, Flags: "TF"},
			{ID: 3, Name: "close", Argc: 1, Flags: "TD"},
			{ID: 4, Name: "fallback", Argc: 1, Flags: "0"},
			{ID: 5, Name: "missing", Argc: 2, Flags: "0"},
		}},
		semanticOverrides: map[string]SyscallMeta{
			"stat": {Name: "stat", Args: []string{"semantic_path", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},
		},
		fallbackOverrides: map[string]SyscallMeta{
			"read":     {Name: "read", Args: []string{"override_fd"}, ArgTypes: []string{"int"}},
			"close":    {Name: "close", Args: []string{"override_fd"}, ArgTypes: []string{"int"}},
			"fallback": {Name: "fallback", Args: []string{"fallback_arg"}, ArgTypes: []string{"long"}},
		},
		aliases: map[string]string{},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertMeta(t, got[1], SyscallMeta{Name: "read", Args: []string{"btf_fd"}, ArgTypes: []string{"unsigned int"}, Flags: "TD"})
	assertMeta(t, got[2], SyscallMeta{Name: "stat", Args: []string{"semantic_path", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}, Flags: "TF"})
	assertMeta(t, got[3], SyscallMeta{Name: "close", Args: []string{"tracepoint_fd"}, ArgTypes: []string{"unsigned int"}, Flags: "TD"})
	assertMeta(t, got[4], SyscallMeta{Name: "fallback", Args: []string{"fallback_arg"}, ArgTypes: []string{"long"}, Flags: "0"})
	assertMeta(t, got[5], SyscallMeta{Name: "missing", Args: []string{"arg0", "arg1"}, ArgTypes: []string{"unsigned long", "unsigned long"}, Flags: "0"})
}

func TestSyscallMetadataResolverReportsSource(t *testing.T) {
	resolver := syscallMetadataResolver{
		btf: map[string]SyscallMeta{
			"read":         {Name: "read", Args: []string{"fd"}, ArgTypes: []string{"int"}},
			"kernel_alias": {Name: "kernel_alias", Args: []string{"fd"}, ArgTypes: []string{"int"}},
		},
		tracepoint: map[string]SyscallMeta{
			"close": {Name: "close", Args: []string{"fd"}, ArgTypes: []string{"unsigned int"}},
		},
		semanticOverrides: map[string]SyscallMeta{
			"stat": {Name: "stat", Args: []string{"path"}, ArgTypes: []string{"const char *"}},
		},
		fallbackOverrides: map[string]SyscallMeta{
			"fallback": {Name: "fallback", Args: []string{"arg"}, ArgTypes: []string{"long"}},
		},
		aliases: map[string]string{"kernel_alias": "alias"},
	}
	cases := []struct {
		name    string
		want    syscallMetadataSource
		wantArg string
	}{
		{name: "read", want: metadataSourceBTF, wantArg: "fd"},
		{name: "alias", want: metadataSourceBTFAlias, wantArg: "fd"},
		{name: "close", want: metadataSourceTracepoint, wantArg: "fd"},
		{name: "stat", want: metadataSourceSemanticOverride, wantArg: "path"},
		{name: "fallback", want: metadataSourceFallbackOverride, wantArg: "arg"},
		{name: "missing", want: metadataSourceDummy, wantArg: "arg0"},
	}
	for _, tc := range cases {
		got := resolver.Resolve(syscallentEntry{Name: tc.name, Argc: 1})
		if got.Source != tc.want || got.Meta.Args[0] != tc.wantArg {
			t.Fatalf("Resolve(%q) = (%s, %#v), want (%s, arg %q)", tc.name, got.Source, got.Meta, tc.want, tc.wantArg)
		}
	}
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
