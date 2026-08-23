package handler

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestBpfCommandCoverageMatchesGeneratedCommands(t *testing.T) {
	catalog := meta.NewCatalog("raw")
	table, ok := catalog.Table("bpf_commands")
	if !ok {
		t.Fatal("generated bpf_commands table is missing")
	}
	if len(table.Entries) != len(bpfCommandCoverageTable) {
		t.Fatalf("coverage entries = %d, generated commands = %d", len(bpfCommandCoverageTable), len(table.Entries))
	}
	for _, entry := range table.Entries {
		spec, ok := bpfCommandCoverageFor(entry.Val)
		if !ok {
			t.Fatalf("BPF command %d (%s) has no coverage entry", entry.Val, entry.Str)
		}
		if spec.name != entry.Str {
			t.Fatalf("BPF command %d coverage name = %q, generated name = %q", entry.Val, spec.name, entry.Str)
		}
		if spec.decoder == 0 || spec.enterContract == "" || spec.exitContract == "" ||
			!validBpfCommandContract(spec.enterContract) || !validBpfCommandContract(spec.exitContract) ||
			spec.evidence == "" || spec.evidenceFlags == 0 || spec.capability == 0 {
			t.Fatalf("BPF command %d has incomplete coverage: %+v", entry.Val, spec)
		}
	}
}

func TestBpfCommandCoverageUsesDenseStableIDs(t *testing.T) {
	for command, spec := range bpfCommandCoverageTable {
		if spec.name == "" {
			t.Fatalf("coverage entry %d is empty", command)
		}
		got, ok := bpfCommandCoverageFor(uint64(command))
		if !ok || got.name != spec.name {
			t.Fatalf("coverage lookup for command %d = %+v, %v", command, got, ok)
		}
	}
}

func TestBpfCommandCoverageEvidenceDoesNotOverclaimCapability(t *testing.T) {
	for command, spec := range bpfCommandCoverageTable {
		hasBoundary := spec.evidenceFlags&bpfEvidenceCapabilityBoundary != 0
		if spec.capability == bpfCommandCapabilityEnvironmentDependent && !hasBoundary {
			t.Fatalf("BPF command %d is environment-dependent without capability evidence", command)
		}
		if spec.capability == bpfCommandCapabilityStable && hasBoundary {
			t.Fatalf("BPF command %d is stable but has capability evidence", command)
		}
	}

	for command, expected := range map[uint64]bpfCommandEvidence{
		8:  bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess,
		9:  bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess,
		32: bpfEvidenceCapabilityBoundary,
		33: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary,
		36: bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary,
		37: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary,
		38: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary,
	} {
		spec, ok := bpfCommandCoverageFor(command)
		if !ok || spec.evidenceFlags != expected {
			t.Fatalf("BPF command %d evidence = %#x, want %#x", command, spec.evidenceFlags, expected)
		}
	}
}

func TestBpfCommandCoverageDeclaresStableOrEnvironmentDependentContract(t *testing.T) {
	for command, spec := range bpfCommandCoverageTable {
		if spec.capability != bpfCommandCapabilityStable && spec.capability != bpfCommandCapabilityEnvironmentDependent {
			t.Fatalf("BPF command %d has unknown capability contract %d", command, spec.capability)
		}
	}
}
