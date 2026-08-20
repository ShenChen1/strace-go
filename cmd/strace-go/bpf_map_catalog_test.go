package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFCoreMapCatalogHasUniqueNamesAndBindings(t *testing.T) {
	seen := make(map[string]struct{}, len(bpfCoreMapCatalog))
	objects := &bpfObjects{}
	for _, spec := range bpfCoreMapCatalog {
		if spec.name == "" {
			t.Fatal("core map catalog contains an empty name")
		}
		if spec.lookup == nil {
			t.Fatalf("core map %q has no generated-object lookup", spec.name)
		}
		if _, exists := seen[spec.name]; exists {
			t.Fatalf("duplicate core map name %q", spec.name)
		}
		seen[spec.name] = struct{}{}

		field := reflect.ValueOf(&objects.bpfMaps).Elem()
		found := false
		for index := 0; index < field.NumField(); index++ {
			if field.Type().Field(index).Tag.Get("ebpf") != spec.name {
				continue
			}
			resource := &ebpf.Map{}
			field.Field(index).Set(reflect.ValueOf(resource))
			if got := spec.lookup(objects); got != resource {
				t.Fatalf("core map %q lookup returned %p, want %p", spec.name, got, resource)
			}
			found = true
			break
		}
		if !found {
			t.Fatalf("core map %q has no generated map field", spec.name)
		}
	}

	generated := taggedBPFResourceNames(reflect.TypeOf(bpfMaps{}))
	if len(seen) != len(generated) {
		t.Fatalf("catalog maps = %d, generated maps = %d", len(seen), len(generated))
	}
	for name := range generated {
		if _, ok := seen[name]; !ok {
			t.Fatalf("generated map %q is missing from core map catalog", name)
		}
	}

	for _, name := range []string{
		bpfMapConfig,
		bpfMapEvents,
		bpfMapPendingAux,
		bpfMapPendingSyscalls,
		bpfMapEnterRoutes,
		bpfMapExitRoutes,
		bpfMapStats,
	} {
		if _, ok := bpfCoreMapSpecByName(name); !ok {
			t.Fatalf("core map catalog is missing %q", name)
		}
	}
}

func TestBPFSharedMapReplacementRejectsUncatalogedMap(t *testing.T) {
	core := &ebpf.Collection{}
	handlers := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"future_shared_map": {},
		},
	}

	_, err := newBPFMapReplacementPlan(core, handlers)
	if err == nil || !strings.Contains(err.Error(), `handler map "future_shared_map" is not in the core map catalog`) {
		t.Fatalf("newBPFMapReplacementPlan() error = %v, want uncataloged map error", err)
	}
}

func TestBPFRuntimeMapConsumersUseCatalog(t *testing.T) {
	root := repoRootForTest(t)
	files := []string{
		"bpf_runtime.go",
		"bpf_config.go",
		"bpf_routes.go",
		"bpf_read_ports.go",
		"bpf_attach.go",
		"syscall_filter.go",
		"bpf_collection_split.go",
	}
	for _, name := range files {
		source := readTextFile(t, filepath.Join(root, "cmd/strace-go", name))
		for _, forbidden := range []string{
			".ArmForkMap",
			".AttachExitedMap",
			".AttachRootsMap",
			".ConfigMap",
			".EnterProgs",
			".EnterRoutes",
			".Events",
			".ExitProgs",
			".ExitRoutes",
			".FilterMap",
			".FdPathScratchMap",
			".MainExitedMap",
			".MmsgBytesProgs",
			".PendingExecMap",
			".PendingSyscalls",
			".PreExecMap",
			".RecvmsgProgs",
			".StackTraces",
			".StatsMap",
			".SyscallFilterMap",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s directly references generated map field %q", name, forbidden)
			}
		}
	}
}
