package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type bpfLoadedHandlerCollections struct {
	collections map[bpfHandlerFamily]*bpfLoadedCollection
	loadOrder   []bpfHandlerFamily
}

func (h *bpfLoadedHandlerCollections) Close() error {
	if h == nil {
		return nil
	}
	var closeErr error
	for index := len(h.loadOrder) - 1; index >= 0; index-- {
		family := h.loadOrder[index]
		if collection := h.collections[family]; collection != nil {
			closeErr = errors.Join(closeErr, collection.Close())
		}
	}
	return closeErr
}

func (h *bpfLoadedHandlerCollections) transferTo(bundle *bpfObjectBundle) {
	if h == nil || bundle == nil {
		return
	}
	for index := len(h.loadOrder) - 1; index >= 0; index-- {
		family := h.loadOrder[index]
		collection := h.collections[family]
		if collection == nil {
			continue
		}
		if closer := collection.transferCloser(); closer != nil {
			bundle.handlerClosers = append(bundle.handlerClosers, closer)
		}
	}
}

type bpfHandlerCollectionLoadFunc func(
	bpfHandlerFamily,
	*ebpf.CollectionSpec,
	*ebpf.Collection,
) (*bpfLoadedCollection, error)

type bpfHandlerCollectionLoadResult struct {
	family     bpfHandlerFamily
	collection *bpfLoadedCollection
	timing     traceBPFSetupTiming
	err        error
}

func loadBPFHandlerCollectionsParallel(
	plan *bpfCollectionPlan,
	core *ebpf.Collection,
	clock traceClock,
	load bpfHandlerCollectionLoadFunc,
) (*bpfLoadedHandlerCollections, []traceBPFSetupTiming, error) {
	if plan == nil || len(plan.handlerSpecs) == 0 {
		return nil, nil, fmt.Errorf("BPF handler collection plan is unavailable")
	}
	if core == nil {
		return nil, nil, fmt.Errorf("BPF core collection is unavailable")
	}
	if clock == nil {
		return nil, nil, fmt.Errorf("BPF handler collection clock is nil")
	}
	if load == nil {
		return nil, nil, fmt.Errorf("BPF handler collection loader is nil")
	}

	results := make([]bpfHandlerCollectionLoadResult, len(bpfHandlerLoadOrder))
	var workers sync.WaitGroup
	workers.Add(len(bpfHandlerLoadOrder))
	for index, family := range bpfHandlerLoadOrder {
		spec := plan.handlerSpecs[family]
		go func(index int, family bpfHandlerFamily, spec *ebpf.CollectionSpec) {
			defer workers.Done()
			result := bpfHandlerCollectionLoadResult{family: family}
			recorder := newBPFSetupRecorder()
			err := measureBPFSetupStage(
				clock,
				recorder,
				bpfHandlerCollectionStage(family),
				func() error {
					if spec == nil || len(spec.Programs) == 0 {
						return nil
					}
					var loadErr error
					result.collection, loadErr = load(family, spec, core)
					return loadErr
				},
			)
			result.err = err
			if timings := recorder.Timings(); len(timings) == 1 {
				result.timing = timings[0]
			}
			results[index] = result
		}(index, family, spec)
	}
	workers.Wait()

	loaded := &bpfLoadedHandlerCollections{
		collections: make(map[bpfHandlerFamily]*bpfLoadedCollection),
		loadOrder:   make([]bpfHandlerFamily, 0, len(results)),
	}
	timings := make([]traceBPFSetupTiming, 0, len(results))
	var loadErr error
	for _, result := range results {
		if result.timing.Stage != "" {
			timings = append(timings, result.timing)
		}
		if result.err != nil {
			loadErr = errors.Join(
				loadErr,
				fmt.Errorf("load %s handler collection: %w", result.family, result.err),
			)
		}
		if result.collection == nil {
			continue
		}
		loaded.collections[result.family] = result.collection
		loaded.loadOrder = append(loaded.loadOrder, result.family)
	}
	return loaded, timings, loadErr
}

func (l *nativeBPFObjectLoader) loadHandlers(
	plan *bpfCollectionPlan,
	core *bpfLoadedCollection,
	clock traceClock,
	observer traceBPFSetupObserver,
) (*bpfLoadedHandlerCollections, error) {
	if plan == nil || len(plan.handlerSpecs) == 0 || core == nil || core.value() == nil {
		return nil, fmt.Errorf("BPF handler collection plan is unavailable")
	}
	coreCollection := core.value()
	var loaded *bpfLoadedHandlerCollections
	var timings []traceBPFSetupTiming
	err := measureBPFSetupStage(clock, observer, bpfSetupHandlerCollectionsStage, func() error {
		var err error
		loaded, timings, err = loadBPFHandlerCollectionsParallel(
			plan,
			coreCollection,
			clock,
			loadBPFHandlerFamily,
		)
		return err
	})
	for _, timing := range timings {
		if observer != nil {
			observer.RecordBPFSetupStage(timing)
		}
	}
	return loaded, err
}

func loadBPFHandlerFamily(
	family bpfHandlerFamily,
	spec *ebpf.CollectionSpec,
	core *ebpf.Collection,
) (*bpfLoadedCollection, error) {
	replacementPlan, err := newBPFMapReplacementPlan(core, spec)
	if err != nil {
		return nil, fmt.Errorf("%s map replacements: %w", family, err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: replacementPlan.replacements,
	})
	if err != nil {
		return nil, fmt.Errorf("%s collection: %w", family, err)
	}
	return &bpfLoadedCollection{collection: collection}, nil
}

func selectedBPFHandlerPrograms(
	loaded *bpfLoadedHandlerCollections,
	selection bpfProgramSelection,
) (map[string]*ebpf.Program, error) {
	if loaded == nil {
		return nil, fmt.Errorf("handler BPF collections are nil")
	}
	programs := make(map[string]*ebpf.Program)
	for _, family := range loaded.loadOrder {
		collection := loaded.collections[family]
		if collection == nil || collection.value() == nil {
			return nil, fmt.Errorf("handler BPF collection %q is unavailable", family)
		}
		for name, program := range collection.value().Programs {
			if isCoreBPFProgramName(name) {
				continue
			}
			if _, exists := programs[name]; exists {
				return nil, fmt.Errorf("handler BPF program %q belongs to multiple families", name)
			}
			if program == nil {
				return nil, fmt.Errorf("handler BPF program %q is nil", name)
			}
			if _, ok := classifyBPFHandlerProgram(name); !ok {
				return nil, fmt.Errorf("handler BPF program %q has no family", name)
			}
			programs[name] = program
		}
	}
	if selection.loadAll {
		return programs, nil
	}
	for name := range selection.programs {
		if isCoreBPFProgramName(name) {
			continue
		}
		if programs[name] == nil {
			return nil, fmt.Errorf("selected handler BPF program %q is unavailable", name)
		}
	}
	return programs, nil
}
