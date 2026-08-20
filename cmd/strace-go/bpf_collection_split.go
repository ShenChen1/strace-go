package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

var bpfHandlerProgramFamilies = buildBPFHandlerProgramFamilies()

func classifyBPFHandlerProgram(name string) (bpfHandlerFamily, bool) {
	family, ok := bpfHandlerProgramFamilies[name]
	return family, ok
}

// bpfMapReplacementPlan describes handler maps that must reuse core state.
// ELF data sections stay private because their global variables are object-local.
type bpfMapReplacementPlan struct {
	replacements map[string]*ebpf.Map
}

func newBPFMapReplacementPlan(
	core *ebpf.Collection,
	handlers *ebpf.CollectionSpec,
) (*bpfMapReplacementPlan, error) {
	if core == nil {
		return nil, fmt.Errorf("core BPF collection is nil")
	}
	if handlers == nil {
		return nil, fmt.Errorf("handler BPF spec is nil")
	}
	replacements := make(map[string]*ebpf.Map)
	for name := range handlers.Maps {
		if isBPFDataSection(name) {
			continue
		}
		if _, ok := bpfCoreMapSpecByName(name); !ok {
			return nil, fmt.Errorf("handler map %q is not in the core map catalog", name)
		}
		resource, ok := core.Maps[name]
		if !ok || resource == nil {
			return nil, fmt.Errorf("core map %q is unavailable", name)
		}
		replacements[name] = resource
	}
	return &bpfMapReplacementPlan{replacements: replacements}, nil
}

func isBPFDataSection(name string) bool {
	return strings.HasPrefix(name, ".")
}

func prepareBPFCollectionPrograms(
	core *ebpf.CollectionSpec,
	handlers map[bpfHandlerFamily]*ebpf.CollectionSpec,
	selection bpfProgramSelection,
) error {
	if core == nil || len(handlers) == 0 {
		return fmt.Errorf("BPF core and handler specs are required")
	}
	if err := validateBPFHandlerSpecFamilies(handlers); err != nil {
		return err
	}
	for name := range selection.programs {
		if _, ok := core.Programs[name]; ok {
			continue
		}
		family, ok := classifyBPFHandlerProgram(name)
		if !ok {
			return fmt.Errorf("selected BPF program %q is unavailable", name)
		}
		spec, familyOK := handlers[family]
		if familyOK && spec != nil {
			if _, ok := spec.Programs[name]; ok {
				continue
			}
		}
		return fmt.Errorf("selected BPF program %q is unavailable", name)
	}
	if selection.loadAll {
		return nil
	}
	coreSelection := selectionForBPFSpec(selection, core)
	if err := pruneBPFProgramSpecs(core, coreSelection); err != nil {
		return fmt.Errorf("prune core programs: %w", err)
	}
	for family, spec := range handlers {
		if spec == nil {
			return fmt.Errorf("handler spec %q is nil", family)
		}
		handlerSelection := selectionForBPFSpec(selection, spec)
		if err := pruneBPFProgramSpecs(spec, handlerSelection); err != nil {
			return fmt.Errorf("prune %s handler programs: %w", family, err)
		}
	}
	return nil
}

func selectionForBPFSpec(
	selection bpfProgramSelection,
	spec *ebpf.CollectionSpec,
) bpfProgramSelection {
	selected := selection
	selected.loadAll = false
	selected.programs = make(map[string]struct{})
	for name := range selection.programs {
		if _, ok := spec.Programs[name]; ok {
			selected.programs[name] = struct{}{}
		}
	}
	return selected
}
