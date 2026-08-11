package main

import (
	"fmt"
	"io"
)

type stableXlatEntry struct {
	name  string
	value string
}

func applyStableXlatFallbacks(name string, prefix *string, entries map[string]string, keys *[]string) {
	fallbacks := map[string]struct {
		prefix  string
		entries []stableXlatEntry
	}{
		"fsmount_flags": {
			prefix:  "FSMOUNT_",
			entries: []stableXlatEntry{{"FSMOUNT_CLOEXEC", "1"}, {"FSMOUNT_NAMESPACE", "2"}},
		},
		"uffd_flags": {
			prefix:  "O_ UFFD_",
			entries: []stableXlatEntry{{"UFFD_USER_MODE_ONLY", "1"}, {"O_NONBLOCK", "2048"}, {"O_CLOEXEC", "524288"}},
		},
	}
	fallback, ok := fallbacks[name]
	if !ok {
		return
	}
	if *prefix == "" {
		*prefix = fallback.prefix
	}
	for _, entry := range fallback.entries {
		addStableXlatEntry(entries, keys, entry)
	}
}

func normalizeXlatPrefix(name string, prefix *string) {
	switch name {
	case "open_tree_flags":
		*prefix = "OPEN_TREE_"
	case "sock_options":
		*prefix = "SO_"
	}
}

func addStableXlatEntry(entries map[string]string, keys *[]string, entry stableXlatEntry) {
	if _, ok := entries[entry.name]; ok {
		return
	}
	entries[entry.name] = entry.value
	for _, key := range *keys {
		if key == entry.name {
			return
		}
	}
	*keys = append(*keys, entry.name)
}

func writeAliasXlatTables(out io.Writer, emitted map[string]bool) {
	if !emitted["pkey_access_rights"] {
		writeStaticXlatTable(out, "pkey_access_rights", "PKEY_", []stableXlatEntry{
			{"PKEY_UNRESTRICTED", "0"},
			{"PKEY_DISABLE_ACCESS", "0x1"},
			{"PKEY_DISABLE_WRITE", "0x2"},
			{"PKEY_DISABLE_EXECUTE", "0x4"},
		})
	}
	if !emitted["mmap_prot64"] {
		writeStaticXlatTable(out, "mmap_prot64", "PROT_", []stableXlatEntry{
			{"PROT_NONE", "0"},
			{"PROT_READ", "1"},
			{"PROT_WRITE", "2"},
			{"PROT_EXEC", "4"},
			{"PROT_GROWSDOWN", "16777216"},
			{"PROT_GROWSUP", "33554432"},
		})
	}
}

func writeStaticXlatTable(out io.Writer, name string, prefix string, entries []stableXlatEntry) {
	fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", name, prefix)
	for _, entry := range entries {
		fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", entry.value, entry.name)
	}
	fmt.Fprintf(out, "\t\t},\n\t},\n")
}

func isCIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
			continue
		}
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}
