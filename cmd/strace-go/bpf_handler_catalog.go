package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfHandlerFamily string

const (
	bpfHandlerEnterGenericFamily    bpfHandlerFamily = "enter_generic"
	bpfHandlerEnterPayloadFamily    bpfHandlerFamily = "enter_payload"
	bpfHandlerEnterPathFamily       bpfHandlerFamily = "enter_path"
	bpfHandlerEnterMemoryFamily     bpfHandlerFamily = "enter_memory"
	bpfHandlerEnterControlFamily    bpfHandlerFamily = "enter_control"
	bpfHandlerEnterStructuredFamily bpfHandlerFamily = "enter_structured"
	bpfHandlerExitFamily            bpfHandlerFamily = "exit"
	bpfHandlerRecvmsgFamily         bpfHandlerFamily = "recvmsg"
)

type bpfHandlerFamilySpec struct {
	family bpfHandlerFamily
	name   string
	stage  traceBPFSetupStage
	load   func() (*ebpf.CollectionSpec, error)
}

var bpfHandlerFamilyCatalog = []bpfHandlerFamilySpec{
	{
		family: bpfHandlerEnterGenericFamily,
		name:   "enter generic",
		stage:  bpfSetupEnterGenericCollectionStage,
		load:   loadBpfEnterGeneric,
	},
	{
		family: bpfHandlerEnterPayloadFamily,
		name:   "enter payload",
		stage:  bpfSetupEnterPayloadCollectionStage,
		load:   loadBpfEnterPayload,
	},
	{
		family: bpfHandlerEnterPathFamily,
		name:   "enter path",
		stage:  bpfSetupEnterPathCollectionStage,
		load:   loadBpfEnterPath,
	},
	{
		family: bpfHandlerEnterMemoryFamily,
		name:   "enter memory",
		stage:  bpfSetupEnterMemoryCollectionStage,
		load:   loadBpfEnterMemory,
	},
	{
		family: bpfHandlerEnterControlFamily,
		name:   "enter control",
		stage:  bpfSetupEnterControlCollectionStage,
		load:   loadBpfEnterControl,
	},
	{
		family: bpfHandlerEnterStructuredFamily,
		name:   "enter structured",
		stage:  bpfSetupEnterStructuredCollectionStage,
		load:   loadBpfEnterStructured,
	},
	{
		family: bpfHandlerExitFamily,
		name:   "exit",
		stage:  bpfSetupExitCollectionStage,
		load:   loadBpfExit,
	},
	{
		family: bpfHandlerRecvmsgFamily,
		name:   "recvmsg",
		stage:  bpfSetupRecvmsgCollectionStage,
		load:   loadBpfRecvmsg,
	},
}

func bpfHandlerFamilySpecByFamily(family bpfHandlerFamily) (bpfHandlerFamilySpec, bool) {
	for _, spec := range bpfHandlerFamilyCatalog {
		if spec.family == family {
			return spec, true
		}
	}
	return bpfHandlerFamilySpec{}, false
}

func bpfHandlerCollectionStage(family bpfHandlerFamily) traceBPFSetupStage {
	spec, ok := bpfHandlerFamilySpecByFamily(family)
	if !ok {
		return traceBPFSetupStage("bpf_unknown_handler_collection_load")
	}
	return spec.stage
}

func validateBPFHandlerFamilySpecs(specs []bpfHandlerFamilySpec) error {
	families := make(map[bpfHandlerFamily]struct{}, len(specs))
	names := make(map[string]struct{}, len(specs))
	stages := make(map[traceBPFSetupStage]struct{}, len(specs))
	for index, spec := range specs {
		if spec.family == "" {
			return fmt.Errorf("handler family catalog entry %d family is empty", index)
		}
		if spec.name == "" {
			return fmt.Errorf("handler family %q name is empty", spec.family)
		}
		if spec.stage == "" {
			return fmt.Errorf("handler family %q stage is empty", spec.family)
		}
		if spec.load == nil {
			return fmt.Errorf("handler family %q loader is nil", spec.family)
		}
		if _, exists := families[spec.family]; exists {
			return fmt.Errorf("duplicate family %q in handler catalog", spec.family)
		}
		if _, exists := names[spec.name]; exists {
			return fmt.Errorf("duplicate name %q in handler catalog", spec.name)
		}
		if _, exists := stages[spec.stage]; exists {
			return fmt.Errorf("duplicate stage %q in handler catalog", spec.stage)
		}
		families[spec.family] = struct{}{}
		names[spec.name] = struct{}{}
		stages[spec.stage] = struct{}{}
	}
	return nil
}

func validateBPFHandlerFamilyCatalog() error {
	if err := validateBPFHandlerFamilySpecs(bpfHandlerFamilyCatalog); err != nil {
		return err
	}
	for _, catalog := range [][]bpfTailCallProgramSpec{
		bpfEnterProgramCatalog,
		bpfExitProgramCatalog,
		bpfRecvmsgProgramCatalog,
		bpfMmsgByteProgramCatalog,
	} {
		for _, program := range catalog {
			if _, ok := bpfHandlerFamilySpecByFamily(program.family); !ok {
				return fmt.Errorf("handler program %q has no family catalog owner %q", program.name, program.family)
			}
		}
	}
	for _, program := range bpfStandaloneProgramCatalog {
		if _, ok := bpfHandlerFamilySpecByFamily(program.family); !ok {
			return fmt.Errorf("standalone handler program %q has no family catalog owner %q", program.name, program.family)
		}
	}
	return nil
}

func validateBPFHandlerSpecFamilies(specs map[bpfHandlerFamily]*ebpf.CollectionSpec) error {
	for family := range specs {
		if _, ok := bpfHandlerFamilySpecByFamily(family); !ok {
			return fmt.Errorf("handler family %q is not in the catalog", family)
		}
	}
	return nil
}
