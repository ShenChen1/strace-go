package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"strace-go/pkg/meta"
)

type traceBPFSetupStage string

const (
	bpfSetupMemlockStage                   traceBPFSetupStage = "bpf_memlock"
	bpfSetupSpecStage                      traceBPFSetupStage = "bpf_spec"
	bpfSetupObjectPrepareStage             traceBPFSetupStage = "bpf_object_prepare"
	bpfSetupCoreCollectionStage            traceBPFSetupStage = "bpf_core_collection_load"
	bpfSetupHandlerCollectionsStage        traceBPFSetupStage = "bpf_handler_collections_load"
	bpfSetupEnterGenericCollectionStage    traceBPFSetupStage = "bpf_enter_generic_collection_load"
	bpfSetupEnterPayloadCollectionStage    traceBPFSetupStage = "bpf_enter_payload_collection_load"
	bpfSetupEnterPathCollectionStage       traceBPFSetupStage = "bpf_enter_path_collection_load"
	bpfSetupEnterMemoryCollectionStage     traceBPFSetupStage = "bpf_enter_memory_collection_load"
	bpfSetupEnterControlCollectionStage    traceBPFSetupStage = "bpf_enter_control_collection_load"
	bpfSetupEnterStructuredCollectionStage traceBPFSetupStage = "bpf_enter_structured_collection_load"
	bpfSetupExitCollectionStage            traceBPFSetupStage = "bpf_exit_collection_load"
	bpfSetupRecvmsgCollectionStage         traceBPFSetupStage = "bpf_recvmsg_collection_load"
	bpfSetupResourceBindStage              traceBPFSetupStage = "bpf_resource_bind"
	bpfSetupRoutePlanStage                 traceBPFSetupStage = "bpf_route_plan"
	bpfSetupRouteMapsStage                 traceBPFSetupStage = "bpf_route_maps"
	bpfSetupProgArraysStage                traceBPFSetupStage = "bpf_prog_arrays"
	bpfSetupTracepointsStage               traceBPFSetupStage = "bpf_tracepoints"
	bpfSetupRecvmsgKretprobeStage          traceBPFSetupStage = "bpf_recvmsg_kretprobe"
)

type traceBPFSetupTiming struct {
	Stage   traceBPFSetupStage
	StartNS uint64
	EndNS   uint64
}

// traceBPFSetupObserver receives completed setup stages without owning BPF resources.
type traceBPFSetupObserver interface {
	RecordBPFSetupStage(timing traceBPFSetupTiming)
}

type bpfSetupRecorder struct {
	timings []traceBPFSetupTiming
}

func newBPFSetupRecorder() *bpfSetupRecorder {
	return &bpfSetupRecorder{}
}

func (r *bpfSetupRecorder) RecordBPFSetupStage(timing traceBPFSetupTiming) {
	if r == nil {
		return
	}
	r.timings = append(r.timings, timing)
}

func (r *bpfSetupRecorder) Timings() []traceBPFSetupTiming {
	if r == nil {
		return nil
	}
	return append([]traceBPFSetupTiming(nil), r.timings...)
}

func measureBPFSetupStage(
	clock traceClock,
	observer traceBPFSetupObserver,
	stage traceBPFSetupStage,
	action func() error,
) error {
	if clock == nil {
		return fmt.Errorf("BPF setup clock is nil")
	}
	if action == nil {
		return fmt.Errorf("BPF setup action for %s is nil", stage)
	}
	startNS := clock.NowMonoNs()
	err := action()
	endNS := clock.NowMonoNs()
	if observer != nil {
		observer.RecordBPFSetupStage(traceBPFSetupTiming{
			Stage:   stage,
			StartNS: startNS,
			EndNS:   endNS,
		})
	}
	return err
}

func setupBPF() (*traceBPFRuntime, error) {
	return setupBPFWithClock(systemTraceClock{})
}

func setupBPFWithClock(clock traceClock) (*traceBPFRuntime, error) {
	return setupBPFWithConfig(clock, traceBPFConfig{})
}

func setupBPFWithConfig(clock traceClock, config traceBPFConfig) (*traceBPFRuntime, error) {
	if clock == nil {
		return nil, fmt.Errorf("BPF setup clock is nil")
	}
	var err error
	config, err = normalizeTraceBPFConfig(config)
	if err != nil {
		return nil, fmt.Errorf("normalize BPF config: %w", err)
	}
	recorder := newBPFSetupRecorder()
	if err := measureBPFSetupStage(clock, recorder, bpfSetupMemlockStage, rlimit.RemoveMemlock); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	specs, err := loadBPFSpecWithTiming(clock, recorder, config)
	if err != nil {
		return nil, err
	}

	routePlan, selection, err := buildBPFSelectionWithTiming(clock, recorder, config)
	if err != nil {
		return nil, err
	}

	bundle, err := loadBPFObjectsWithTiming(
		clock,
		recorder,
		specs,
		selection,
		&nativeBPFObjectLoader{},
	)
	if err != nil {
		return nil, err
	}
	core := bundle.core
	if err := measureBPFSetupStage(clock, recorder, bpfSetupRouteMapsStage, func() error {
		return configureBPFRouteMaps(core, bundle.programs, routePlan)
	}); err != nil {
		return nil, closeBPFSetupFailure("configure BPF route maps", err, nil, bundle)
	}

	attacher := newBpfAttacherWithPrograms(core, bundle.programs)
	if err := measureBPFSetupStage(clock, recorder, bpfSetupProgArraysStage, func() error {
		return attacher.populateProgArraysFor(selection)
	}); err != nil {
		return nil, closeBPFSetupFailure("populate BPF program arrays", err, nil, bundle)
	}
	var links []link.Link
	if err := measureBPFSetupStage(clock, recorder, bpfSetupTracepointsStage, func() error {
		var err error
		links, err = attacher.attachRequired()
		return err
	}); err != nil {
		return nil, closeBPFSetupFailure("attach required BPF programs", err, links, bundle)
	}
	if err := measureBPFSetupStage(clock, recorder, bpfSetupRecvmsgKretprobeStage, func() error {
		kprobe, err := attacher.attachOptionalRecvmsgFor(selection.recvmsgKretprobe)
		if err != nil {
			log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data: %v", err)
			return nil
		}
		if kprobe != nil {
			links = append(links, kprobe)
		}
		return nil
	}); err != nil {
		return nil, closeBPFSetupFailure("attach optional BPF programs", err, links, bundle)
	}

	extraResources := bundle.extraResources.transfer()
	handlerResources := bundle.handlerResources.transfer()
	return &traceBPFRuntime{
		core:             core,
		programs:         bundle.programs,
		links:            links,
		handlerResources: handlerResources,
		extraResources:   extraResources,
		setupTimings:     recorder.Timings(),
	}, nil
}

func loadBPFSpecWithTiming(
	clock traceClock,
	recorder traceBPFSetupObserver,
	config traceBPFConfig,
) (*bpfCollectionSpecSet, error) {
	var err error
	config, err = normalizeTraceBPFConfig(config)
	if err != nil {
		return nil, fmt.Errorf("normalize BPF config: %w", err)
	}
	var specs bpfCollectionSpecSet
	err = measureBPFSetupStage(clock, recorder, bpfSetupSpecStage, func() error {
		core, err := loadBpf()
		if err != nil {
			return fmt.Errorf("load BPF core spec: %w", err)
		}
		if err := configureBPFEventRingbufCapacity(core, config.eventRingbufCapacity); err != nil {
			return fmt.Errorf("configure BPF event ringbuf: %w", err)
		}
		if err := setSyscallVariables(core); err != nil {
			return fmt.Errorf("resolve BPF core syscall variables: %w", err)
		}
		handlers, err := loadBPFHandlerSpecs()
		if err != nil {
			return fmt.Errorf("load BPF handler specs: %w", err)
		}
		for family, spec := range handlers {
			if err := configureBPFEventRingbufCapacity(spec, config.eventRingbufCapacity); err != nil {
				return fmt.Errorf("configure %s event ringbuf: %w", family, err)
			}
		}
		specs = bpfCollectionSpecSet{core: core, handlers: handlers}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &specs, nil
}

func loadBPFHandlerSpecs() (map[bpfHandlerFamily]*ebpf.CollectionSpec, error) {
	if err := validateBPFHandlerFamilyCatalog(); err != nil {
		return nil, fmt.Errorf("validate BPF handler family catalog: %w", err)
	}
	specs := make(map[bpfHandlerFamily]*ebpf.CollectionSpec, len(bpfHandlerFamilyCatalog))
	for _, loader := range bpfHandlerFamilyCatalog {
		spec, err := loader.load()
		if err != nil {
			return nil, fmt.Errorf("load %s handler spec: %w", loader.name, err)
		}
		if err := setSyscallVariables(spec); err != nil {
			return nil, fmt.Errorf("resolve %s handler syscall variables: %w", loader.name, err)
		}
		specs[loader.family] = spec
	}
	return specs, nil
}

func buildBPFSelectionWithTiming(
	clock traceClock,
	recorder traceBPFSetupObserver,
	config traceBPFConfig,
) (bpfRoutePlan, bpfProgramSelection, error) {
	var routePlan bpfRoutePlan
	var selection bpfProgramSelection
	err := measureBPFSetupStage(clock, recorder, bpfSetupRoutePlanStage, func() error {
		fullPlan, err := newBPFRoutePlan(meta.SyscallTable)
		if err != nil {
			return err
		}
		routePlan = selectBPFRoutePlan(fullPlan, config)
		selection, err = newBPFProgramSelection(routePlan, meta.SyscallTable, config)
		return err
	})
	if err != nil {
		return bpfRoutePlan{}, bpfProgramSelection{}, fmt.Errorf("build BPF route plan: %w", err)
	}
	return routePlan, selection, nil
}

func loadBPFObjectsWithTiming(
	clock traceClock,
	recorder traceBPFSetupObserver,
	specs *bpfCollectionSpecSet,
	selection bpfProgramSelection,
	loader bpfObjectLoader,
) (*bpfObjectBundle, error) {
	if loader == nil {
		return nil, fmt.Errorf("BPF object loader is nil")
	}
	var plan *bpfCollectionPlan
	if err := measureBPFSetupStage(clock, recorder, bpfSetupObjectPrepareStage, func() error {
		var err error
		plan, err = loader.prepare(specs, selection)
		return err
	}); err != nil {
		return nil, fmt.Errorf("prepare BPF collection: %w", err)
	}

	var core *bpfLoadedCollection
	if err := measureBPFSetupStage(clock, recorder, bpfSetupCoreCollectionStage, func() error {
		var err error
		core, err = loader.loadCore(plan)
		return err
	}); err != nil {
		return nil, fmt.Errorf("load BPF core collection: %w", errors.Join(err, core.Close()))
	}
	if core == nil {
		return nil, fmt.Errorf("BPF object loader returned nil core collection")
	}

	handlers, err := loader.loadHandlers(plan, core, clock, recorder)
	if err != nil {
		return nil, fmt.Errorf(
			"load BPF handler collections: %w",
			errors.Join(err, handlers.Close(), core.Close()),
		)
	}
	if handlers == nil {
		return nil, fmt.Errorf(
			"load BPF handler collection: %w",
			errors.Join(fmt.Errorf("BPF object loader returned nil handler collection"), core.Close()),
		)
	}
	loaded := &bpfLoadedCollectionSet{core: core, handlers: handlers, selection: selection}

	var bundle *bpfObjectBundle
	err = measureBPFSetupStage(clock, recorder, bpfSetupResourceBindStage, func() error {
		var err error
		bundle, err = loader.bind(loaded)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("bind BPF resources: %w", errors.Join(err, loaded.Close()))
	}
	if bundle == nil {
		return nil, fmt.Errorf(
			"bind BPF resources: %w",
			errors.Join(fmt.Errorf("BPF object loader returned nil bundle"), loaded.Close()),
		)
	}
	loaded.transferTo(bundle)
	return bundle, nil
}

func closeBPFSetupFailure(
	message string,
	primary error,
	links []link.Link,
	bundle *bpfObjectBundle,
) error {
	return fmt.Errorf("%s: %w", message, errors.Join(primary, closeTracepointLinks(links), bundle.Close()))
}
