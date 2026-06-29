package main

import "testing"

func TestApplyStableXlatFallbacksAddsMissingEntries(t *testing.T) {
	prefix := ""
	entries := map[string]string{"O_CLOEXEC": "524288"}
	keys := []string{"O_CLOEXEC"}

	applyStableXlatFallbacks("uffd_flags", &prefix, entries, &keys)

	if prefix != "O_ UFFD_" {
		t.Fatalf("prefix = %q, want O_ UFFD_", prefix)
	}
	if entries["UFFD_USER_MODE_ONLY"] != "1" {
		t.Fatalf("UFFD_USER_MODE_ONLY = %q, want 1", entries["UFFD_USER_MODE_ONLY"])
	}
	if entries["O_CLOEXEC"] != "524288" {
		t.Fatalf("O_CLOEXEC was overwritten: %q", entries["O_CLOEXEC"])
	}
	if len(keys) != 3 {
		t.Fatalf("keys = %#v, want three stable entries", keys)
	}
}
