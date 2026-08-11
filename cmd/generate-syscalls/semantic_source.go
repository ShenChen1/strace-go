package main

import (
	"fmt"
	"sort"
	"strings"
)

// syscallentEntry carries formatter semantics; its ID is assigned by the ABI source.
type syscallentEntry struct {
	ID    int
	Name  string
	Argc  int
	Flags string
}

// syscallSemanticEntry is the checked-in semantic catalog record without a kernel ID.
type syscallSemanticEntry struct {
	Argc  int
	Flags string
}

type checkedInSyscallSemanticSource struct{}

func (checkedInSyscallSemanticSource) LoadSyscallEntries() ([]syscallentEntry, error) {
	entries := make([]syscallentEntry, 0, len(syscallSemanticCatalog))
	for name, semantic := range syscallSemanticCatalog {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("semantic catalog contains empty syscall name")
		}
		if semantic.Argc < 0 {
			return nil, fmt.Errorf("semantic catalog entry %s has negative arity", name)
		}
		if semantic.Flags == "" {
			return nil, fmt.Errorf("semantic catalog entry %s has empty flags", name)
		}
		entries = append(entries, syscallentEntry{Name: name, Argc: semantic.Argc, Flags: semantic.Flags})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}
