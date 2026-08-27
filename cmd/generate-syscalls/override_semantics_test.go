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
}

func TestFlockUsesStraceOperationName(t *testing.T) {
	meta, ok := semanticOverrides["flock"]
	if !ok {
		t.Fatal("flock must be a semantic override")
	}
	if len(meta.Args) != 2 || meta.Args[1] != "op" {
		t.Fatalf("flock arguments = %#v, want fd/op", meta.Args)
	}
}

func TestSplitOffsetOverridesStaySemantic(t *testing.T) {
	for _, name := range []string{"preadv", "pwritev"} {
		spec, ok := semanticOverrideSpecs[name]
		if !ok {
			t.Fatalf("%s must remain a semantic override", name)
		}
		if spec.Reason != "strace_split_offset_signature" {
			t.Fatalf("%s reason = %q, want strace_split_offset_signature", name, spec.Reason)
		}
		if len(spec.OverrideArgs) != 5 || spec.OverrideArgs[3] != "pos_l" || spec.OverrideArgs[4] != "pos_h" {
			t.Fatalf("%s args = %#v, want split offset raw ABI", name, spec.OverrideArgs)
		}
	}
}

func TestSplitOffsetOverridesWinOverLogicalArity(t *testing.T) {
	for _, name := range []string{"preadv", "pwritev"} {
		resolver := syscallMetadataResolver{
			tracepoint: map[string]SyscallMeta{name: {
				Name: name, Args: []string{"fd", "vec", "vlen", "pos_l", "pos_h"},
				ArgTypes: []string{"unsigned long", "const struct iovec *", "unsigned long", "unsigned long", "unsigned long"},
			}},
			semanticOverrides: semanticOverrides,
		}
		got := resolver.Resolve(syscallentEntry{Name: name, Argc: 4, Flags: "TD"})
		if got.Source != metadataSourceSemanticOverride || len(got.Meta.Args) != 5 {
			t.Fatalf("Resolve(%s) = (%s, %#v), want five-argument semantic override", name, got.Source, got.Meta.Args)
		}
	}
}
