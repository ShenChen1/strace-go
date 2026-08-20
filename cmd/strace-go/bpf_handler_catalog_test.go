package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFHandlerFamilyCatalogHasStableMetadata(t *testing.T) {
	want := []struct {
		family bpfHandlerFamily
		name   string
		stage  traceBPFSetupStage
	}{
		{bpfHandlerEnterGenericFamily, "enter generic", bpfSetupEnterGenericCollectionStage},
		{bpfHandlerEnterPayloadFamily, "enter payload", bpfSetupEnterPayloadCollectionStage},
		{bpfHandlerEnterPathFamily, "enter path", bpfSetupEnterPathCollectionStage},
		{bpfHandlerEnterMemoryFamily, "enter memory", bpfSetupEnterMemoryCollectionStage},
		{bpfHandlerEnterControlFamily, "enter control", bpfSetupEnterControlCollectionStage},
		{bpfHandlerEnterStructuredFamily, "enter structured", bpfSetupEnterStructuredCollectionStage},
		{bpfHandlerExitFamily, "exit", bpfSetupExitCollectionStage},
		{bpfHandlerRecvmsgFamily, "recvmsg", bpfSetupRecvmsgCollectionStage},
	}
	if len(bpfHandlerFamilyCatalog) != len(want) {
		t.Fatalf("handler family catalog length = %d, want %d", len(bpfHandlerFamilyCatalog), len(want))
	}
	for index, expected := range want {
		got := bpfHandlerFamilyCatalog[index]
		if got.family != expected.family || got.name != expected.name || got.stage != expected.stage {
			t.Fatalf("catalog[%d] = {family:%q name:%q stage:%q}, want {family:%q name:%q stage:%q}",
				index, got.family, got.name, got.stage, expected.family, expected.name, expected.stage)
		}
		if got.load == nil {
			t.Fatalf("catalog[%d] loader is nil", index)
		}
	}
	if err := validateBPFHandlerFamilyCatalog(); err != nil {
		t.Fatalf("validateBPFHandlerFamilyCatalog() error = %v", err)
	}
}

func TestBPFHandlerFamilyCatalogRejectsInvalidMetadata(t *testing.T) {
	loader := func() (*ebpf.CollectionSpec, error) { return nil, nil }
	base := bpfHandlerFamilySpec{
		family: bpfHandlerFamily("test"),
		name:   "test",
		stage:  traceBPFSetupStage("test_stage"),
		load:   loader,
	}
	tests := []struct {
		name    string
		catalog []bpfHandlerFamilySpec
		want    string
	}{
		{
			name:    "empty family",
			catalog: []bpfHandlerFamilySpec{{name: base.name, stage: base.stage, load: loader}},
			want:    "family is empty",
		},
		{
			name:    "empty name",
			catalog: []bpfHandlerFamilySpec{{family: base.family, stage: base.stage, load: loader}},
			want:    "name is empty",
		},
		{
			name:    "empty stage",
			catalog: []bpfHandlerFamilySpec{{family: base.family, name: base.name, load: loader}},
			want:    "stage is empty",
		},
		{
			name:    "nil loader",
			catalog: []bpfHandlerFamilySpec{{family: base.family, name: base.name, stage: base.stage}},
			want:    "loader is nil",
		},
		{
			name:    "duplicate family",
			catalog: []bpfHandlerFamilySpec{base, base},
			want:    "duplicate family",
		},
		{
			name: "duplicate name",
			catalog: []bpfHandlerFamilySpec{
				base,
				{family: bpfHandlerFamily("other"), name: base.name, stage: traceBPFSetupStage("other_stage"), load: loader},
			},
			want: "duplicate name",
		},
		{
			name: "duplicate stage",
			catalog: []bpfHandlerFamilySpec{
				base,
				{family: bpfHandlerFamily("other"), name: "other", stage: base.stage, load: loader},
			},
			want: "duplicate stage",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateBPFHandlerFamilySpecs(test.catalog)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateBPFHandlerFamilySpecs() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestBPFHandlerFamilyCatalogCoversProgramCatalog(t *testing.T) {
	for _, catalog := range [][]bpfTailCallProgramSpec{
		bpfEnterProgramCatalog,
		bpfExitProgramCatalog,
		bpfRecvmsgProgramCatalog,
		bpfMmsgByteProgramCatalog,
	} {
		for _, program := range catalog {
			if _, ok := bpfHandlerFamilySpecByFamily(program.family); !ok {
				t.Fatalf("program %q has no handler family catalog owner %q", program.name, program.family)
			}
		}
	}
	for _, program := range bpfStandaloneProgramCatalog {
		if _, ok := bpfHandlerFamilySpecByFamily(program.family); !ok {
			t.Fatalf("standalone program %q has no handler family catalog owner %q", program.name, program.family)
		}
	}
}

func TestBPFHandlerSpecFamiliesRejectUnknownFamily(t *testing.T) {
	err := validateBPFHandlerSpecFamilies(map[bpfHandlerFamily]*ebpf.CollectionSpec{
		bpfHandlerFamily("future"): {},
	})
	if err == nil || !strings.Contains(err.Error(), `handler family "future" is not in the catalog`) {
		t.Fatalf("validateBPFHandlerSpecFamilies() error = %v, want unknown family", err)
	}
}

func TestBPFHandlerCollectionStageUsesCatalog(t *testing.T) {
	for _, spec := range bpfHandlerFamilyCatalog {
		if got := bpfHandlerCollectionStage(spec.family); got != spec.stage {
			t.Fatalf("family %q stage = %q, want %q", spec.family, got, spec.stage)
		}
	}
	const unknownStage = traceBPFSetupStage("bpf_unknown_handler_collection_load")
	if got := bpfHandlerCollectionStage(bpfHandlerFamily("future")); got != unknownStage {
		t.Fatalf("unknown family stage = %q, want %q", got, unknownStage)
	}
}

func TestBPFHandlerCatalogOwnsProductionMetadata(t *testing.T) {
	root := repoRootForTest(t)
	setupSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_setup.go"))
	collectionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_handler_collections.go"))
	splitSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_collection_split.go"))
	if !strings.Contains(setupSource, "for _, loader := range bpfHandlerFamilyCatalog") {
		t.Fatal("BPF setup does not load handler specs from the family catalog")
	}
	if !strings.Contains(collectionSource, "for index, familySpec := range bpfHandlerFamilyCatalog") {
		t.Fatal("handler collection loader does not use the family catalog order")
	}
	for name, source := range map[string]string{
		"setup":       setupSource,
		"collections": collectionSource,
		"split":       splitSource,
	} {
		for _, forbidden := range []string{
			"bpfHandlerLoadOrder",
			"loaders := []struct",
			"switch family",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s still contains duplicate handler metadata %q", name, forbidden)
			}
		}
	}
}
