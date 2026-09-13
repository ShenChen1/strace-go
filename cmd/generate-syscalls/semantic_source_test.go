package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDefaultLoaderUsesCheckedInSemanticSource(t *testing.T) {
	loader := newDefaultSyscallMetadataLoader()
	if _, ok := loader.semanticSource.(checkedInSyscallSemanticSource); !ok {
		t.Fatalf("semantic source = %T, want checkedInSyscallSemanticSource", loader.semanticSource)
	}
}

func TestCheckedInSemanticSourceCoversUnixNumbers(t *testing.T) {
	numbers, err := (unixSyscallSource{}).LoadSyscallNumbers()
	if err != nil {
		t.Fatalf("LoadSyscallNumbers() error = %v", err)
	}
	entries, err := (checkedInSyscallSemanticSource{}).LoadSyscallEntries()
	if err != nil {
		t.Fatalf("LoadSyscallEntries() error = %v", err)
	}
	if len(entries) < len(numbers) {
		t.Fatalf("semantic catalog size = %d, unix source size = %d", len(entries), len(numbers))
	}
	semanticNames := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		semanticNames[entry.Name] = struct{}{}
	}
	for _, number := range numbers {
		if _, ok := semanticNames[number.Name]; !ok {
			t.Fatalf("semantic catalog missing %q", number.Name)
		}
	}
}

func TestCheckedInSemanticSourceIsSortedAndStable(t *testing.T) {
	source := checkedInSyscallSemanticSource{}
	first, err := source.LoadSyscallEntries()
	if err != nil {
		t.Fatalf("first LoadSyscallEntries() error = %v", err)
	}
	second, err := source.LoadSyscallEntries()
	if err != nil {
		t.Fatalf("second LoadSyscallEntries() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("semantic entries are not stable")
	}
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i].Name < first[j].Name }) {
		t.Fatalf("semantic entries are not sorted by name")
	}
}

func TestCheckedInSemanticSourceIncludesCurrentKernelSyscalls(t *testing.T) {
	want := map[string]syscallSemanticEntry{
		"file_getattr":     {Argc: 5, Flags: "TD|TF"},
		"file_setattr":     {Argc: 5, Flags: "TD|TF"},
		"listns":           {Argc: 4, Flags: "0"},
		"rseq_slice_yield": {Argc: 0, Flags: "0"},
		"uprobe":           {Argc: 0, Flags: "0"},
	}
	for name, expected := range want {
		if got, ok := syscallSemanticCatalog[name]; !ok || got != expected {
			t.Fatalf("semantic catalog[%q] = %#v, want %#v", name, got, expected)
		}
	}
}

func TestCheckedInSemanticSourceRejectsInvalidCatalogEntry(t *testing.T) {
	original := syscallSemanticCatalog
	syscallSemanticCatalog = map[string]syscallSemanticEntry{"bad": {Argc: -1, Flags: "0"}}
	t.Cleanup(func() { syscallSemanticCatalog = original })

	_, err := (checkedInSyscallSemanticSource{}).LoadSyscallEntries()
	if err == nil || !strings.Contains(err.Error(), "negative arity") {
		t.Fatalf("LoadSyscallEntries() error = %v, want negative arity error", err)
	}
}
