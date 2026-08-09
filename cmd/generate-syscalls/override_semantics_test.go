package main

import "testing"

func TestSemanticOverrideSpecsMatchResolvedOverrides(t *testing.T) {
	for name, spec := range semanticOverrideSpecs {
		override, ok := semanticOverrides[name]
		if !ok {
			t.Fatalf("semantic override spec %q has no resolved override", name)
		}
		btfMeta := SyscallMeta{
			Name:     name,
			Args:     spec.BTFArgs,
			ArgTypes: spec.BTFType,
		}
		rows := overrideAuditRows(
			map[string]SyscallMeta{name: override},
			map[string]SyscallMeta{name: btfMeta},
			nil,
			nil,
		)
		if len(rows) != 1 {
			t.Fatalf("overrideAuditRows(%q) len = %d, want 1", name, len(rows))
		}
		row := rows[0]
		if row.Status != overrideAuditSemanticOverride || row.Reason != spec.Reason {
			t.Fatalf("overrideAuditRows(%q) = (%s, %q), want semantic_override %q", name, row.Status, row.Reason, spec.Reason)
		}
	}
}

func TestMemoryPointerOverridesStaySemantic(t *testing.T) {
	for _, name := range []string{"mprotect", "munmap"} {
		if _, ok := semanticOverrides[name]; !ok {
			t.Fatalf("%s must remain a semantic override", name)
		}
		if _, ok := fallbackOverrides[name]; ok {
			t.Fatalf("%s must not be a fallback override", name)
		}
	}
}

func TestExecveatUsesStraceDirectoryFDName(t *testing.T) {
	meta, ok := semanticOverrides["execveat"]
	if !ok {
		t.Fatal("execveat must be a semantic override")
	}
	if meta.Args[0] != "dfd" {
		t.Fatalf("execveat first argument = %q, want dfd", meta.Args[0])
	}
	if _, ok := fallbackOverrides["execveat"]; ok {
		t.Fatal("execveat must not be a fallback override")
	}
}
