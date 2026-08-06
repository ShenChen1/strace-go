package main

import "testing"

func TestSemanticOverrideSpecsMatchManualOverrides(t *testing.T) {
	for name, spec := range semanticOverrideSpecs {
		override, ok := manualOverrides[name]
		if !ok {
			t.Fatalf("semantic override spec %q has no manual override", name)
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
