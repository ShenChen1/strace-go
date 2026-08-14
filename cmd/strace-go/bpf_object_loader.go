package main

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/cilium/ebpf"
)

type bpfObjectBundle struct {
	objects        *bpfObjects
	programs       bpfProgramProvider
	handlerClosers []io.Closer
	extraClosers   []io.Closer
}

type bpfCollectionSpecSet struct {
	core     *ebpf.CollectionSpec
	handlers map[bpfHandlerFamily]*ebpf.CollectionSpec
}

// bpfCollectionPlan owns prepared core and family specs until they load.
type bpfCollectionPlan struct {
	coreSpec     *ebpf.CollectionSpec
	handlerSpecs map[bpfHandlerFamily]*ebpf.CollectionSpec
	selection    bpfProgramSelection
}

// bpfLoadedCollection is the temporary owner for one collection.
type bpfLoadedCollection struct {
	collection *ebpf.Collection
	closer     io.Closer
	closed     bool
	detached   bool
}

type bpfCollectionCloser struct {
	collection *ebpf.Collection
}

func (c *bpfCollectionCloser) Close() error {
	if c == nil || c.collection == nil {
		return nil
	}
	c.collection.Close()
	c.collection = nil
	return nil
}

func (c *bpfLoadedCollection) Close() error {
	if c == nil || c.closed || c.detached {
		return nil
	}
	c.closed = true
	if c.closer != nil {
		return c.closer.Close()
	}
	if c.collection != nil {
		c.collection.Close()
	}
	return nil
}

func (c *bpfLoadedCollection) detach() {
	if c == nil {
		return
	}
	c.detached = true
	c.collection = nil
	c.closer = nil
}

func (c *bpfLoadedCollection) value() *ebpf.Collection {
	if c == nil || c.detached {
		return nil
	}
	return c.collection
}

func (c *bpfLoadedCollection) transferCloser() io.Closer {
	if c == nil || c.closed || c.detached {
		return nil
	}
	closer := c.closer
	if closer == nil {
		closer = &bpfCollectionCloser{collection: c.collection}
	}
	c.detached = true
	c.collection = nil
	c.closer = nil
	return closer
}

type bpfLoadedCollectionSet struct {
	core      *bpfLoadedCollection
	handlers  *bpfLoadedHandlerCollections
	selection bpfProgramSelection
}

func (s *bpfLoadedCollectionSet) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.handlers.Close(), s.core.Close())
}

func (s *bpfLoadedCollectionSet) transferTo(bundle *bpfObjectBundle) {
	if s == nil || bundle == nil {
		return
	}
	if s.core != nil {
		s.core.detach()
	}
	if s.handlers != nil {
		s.handlers.transferTo(bundle)
	}
}

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

// bpfObjectLoader is the ownership boundary between setup orchestration and
// a concrete core/handler collection backend.
type bpfObjectLoader interface {
	prepare(*bpfCollectionSpecSet, bpfProgramSelection) (*bpfCollectionPlan, error)
	loadCore(*bpfCollectionPlan) (*bpfLoadedCollection, error)
	loadHandlers(
		*bpfCollectionPlan,
		*bpfLoadedCollection,
		traceClock,
		traceBPFSetupObserver,
	) (*bpfLoadedHandlerCollections, error)
	bind(*bpfLoadedCollectionSet) (*bpfObjectBundle, error)
}

type nativeBPFObjectLoader struct{}

func (l *nativeBPFObjectLoader) prepare(
	specs *bpfCollectionSpecSet,
	selection bpfProgramSelection,
) (*bpfCollectionPlan, error) {
	if specs == nil || specs.core == nil || len(specs.handlers) == 0 {
		return nil, fmt.Errorf("BPF core and handler specs are required")
	}
	coreSpec := specs.core.Copy()
	handlerSpecs := make(map[bpfHandlerFamily]*ebpf.CollectionSpec, len(specs.handlers))
	for family, spec := range specs.handlers {
		if spec == nil {
			return nil, fmt.Errorf("handler spec %q is nil", family)
		}
		handlerSpecs[family] = spec.Copy()
	}
	if err := prepareBPFCollectionPrograms(coreSpec, handlerSpecs, selection); err != nil {
		return nil, fmt.Errorf("prepare selected BPF programs: %w", err)
	}
	return &bpfCollectionPlan{
		coreSpec:     coreSpec,
		handlerSpecs: handlerSpecs,
		selection:    selection,
	}, nil
}

func (l *nativeBPFObjectLoader) loadCore(plan *bpfCollectionPlan) (*bpfLoadedCollection, error) {
	if plan == nil || plan.coreSpec == nil {
		return nil, fmt.Errorf("BPF core collection plan is unavailable")
	}
	core, err := ebpf.NewCollection(plan.coreSpec)
	if err != nil {
		return nil, err
	}
	return &bpfLoadedCollection{collection: core}, nil
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
	loaded := &bpfLoadedHandlerCollections{
		collections: make(map[bpfHandlerFamily]*bpfLoadedCollection),
	}
	for _, family := range bpfHandlerLoadOrder {
		spec := plan.handlerSpecs[family]
		var collection *bpfLoadedCollection
		stage := bpfHandlerCollectionStage(family)
		err := measureBPFSetupStage(clock, observer, stage, func() error {
			if spec == nil || len(spec.Programs) == 0 {
				return nil
			}
			var err error
			collection, err = loadBPFHandlerFamily(spec, coreCollection)
			return err
		})
		if err != nil {
			return loaded, fmt.Errorf("load %s handler collection: %w", family, err)
		}
		if collection != nil {
			loaded.collections[family] = collection
			loaded.loadOrder = append(loaded.loadOrder, family)
		}
	}
	return loaded, nil
}

func loadBPFHandlerFamily(
	spec *ebpf.CollectionSpec,
	core *ebpf.Collection,
) (*bpfLoadedCollection, error) {
	replacementPlan, err := newBPFMapReplacementPlan(core, spec)
	if err != nil {
		return nil, err
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: replacementPlan.replacements,
	})
	if err != nil {
		return nil, err
	}
	return &bpfLoadedCollection{collection: collection}, nil
}

func (l *nativeBPFObjectLoader) bind(loaded *bpfLoadedCollectionSet) (*bpfObjectBundle, error) {
	if loaded == nil {
		return nil, fmt.Errorf("loaded BPF collections are unavailable")
	}
	core := loaded.core.value()
	if core == nil || loaded.handlers == nil {
		return nil, fmt.Errorf("loaded BPF core or handler collections are unavailable")
	}
	objects := &bpfObjects{}
	if err := assignBPFCollection(objects, core); err != nil {
		return nil, err
	}
	programs, err := selectedBPFHandlerPrograms(loaded.handlers, loaded.selection)
	if err != nil {
		return nil, err
	}
	extraClosers := collectBPFExtraClosers(core)
	return &bpfObjectBundle{
		objects:      objects,
		programs:     newBPFProgramCatalog(objects, programs),
		extraClosers: extraClosers,
	}, nil
}

func assignBPFCollection(objects *bpfObjects, collection *ebpf.Collection) error {
	if objects == nil || collection == nil {
		return fmt.Errorf("BPF objects or collection is nil")
	}
	if err := assignBPFTaggedFields(
		reflect.ValueOf(&objects.bpfPrograms).Elem(),
		bpfProgramsAsAny(collection.Programs),
		false,
	); err != nil {
		return fmt.Errorf("assign BPF programs: %w", err)
	}
	if err := assignBPFTaggedFields(
		reflect.ValueOf(&objects.bpfMaps).Elem(),
		bpfMapsAsAny(collection.Maps),
		true,
	); err != nil {
		return fmt.Errorf("assign BPF maps: %w", err)
	}
	return nil
}

func assignBPFTaggedFields(target reflect.Value, resources map[string]any, requireAll bool) error {
	if target.Kind() != reflect.Struct {
		return fmt.Errorf("BPF resource target is not a struct")
	}
	for index := 0; index < target.NumField(); index++ {
		fieldType := target.Type().Field(index)
		name := fieldType.Tag.Get("ebpf")
		if name == "" {
			continue
		}
		resource, ok := resources[name]
		if !ok {
			if requireAll {
				return fmt.Errorf("missing BPF resource %q", name)
			}
			continue
		}
		value := reflect.ValueOf(resource)
		field := target.Field(index)
		if !value.Type().AssignableTo(field.Type()) {
			return fmt.Errorf("BPF resource %q has type %s, want %s", name, value.Type(), field.Type())
		}
		field.Set(value)
	}
	return nil
}

func bpfProgramsAsAny(resources map[string]*ebpf.Program) map[string]any {
	converted := make(map[string]any, len(resources))
	for name, resource := range resources {
		converted[name] = resource
	}
	return converted
}

func bpfMapsAsAny(resources map[string]*ebpf.Map) map[string]any {
	converted := make(map[string]any, len(resources))
	for name, resource := range resources {
		converted[name] = resource
	}
	return converted
}

func collectBPFExtraClosers(collection *ebpf.Collection) []io.Closer {
	if collection == nil {
		return nil
	}
	knownPrograms := taggedBPFResourceNames(reflect.TypeOf(bpfPrograms{}))
	knownMaps := taggedBPFResourceNames(reflect.TypeOf(bpfMaps{}))
	type namedCloser struct {
		name   string
		closer io.Closer
	}
	var extras []namedCloser
	for name, program := range collection.Programs {
		if _, ok := knownPrograms[name]; !ok {
			extras = append(extras, namedCloser{name: name, closer: program})
		}
	}
	for name, bpfMap := range collection.Maps {
		if _, ok := knownMaps[name]; !ok {
			extras = append(extras, namedCloser{name: name, closer: bpfMap})
		}
	}
	sort.Slice(extras, func(i, j int) bool { return extras[i].name < extras[j].name })
	closers := make([]io.Closer, 0, len(extras))
	for _, extra := range extras {
		closers = append(closers, extra.closer)
	}
	return closers
}

func taggedBPFResourceNames(resourceType reflect.Type) map[string]struct{} {
	names := make(map[string]struct{}, resourceType.NumField())
	for index := 0; index < resourceType.NumField(); index++ {
		if name := resourceType.Field(index).Tag.Get("ebpf"); name != "" {
			names[name] = struct{}{}
		}
	}
	return names
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

func isCoreBPFProgramName(name string) bool {
	switch name {
	case "trace_sys_enter", "trace_sys_exit",
		"trace_sched_process_fork", "trace_sched_process_exec",
		"trace_sched_process_exit", "trace_sched_process_free":
		return true
	default:
		return false
	}
}

func (b *bpfObjectBundle) Close() error {
	if b == nil {
		return nil
	}
	handlerErr := closeBPFExtraResources(b.handlerClosers)
	b.handlerClosers = nil
	var objectErr error
	if b.objects != nil {
		objectErr = b.objects.Close()
		b.objects = nil
	}
	extraErr := closeBPFExtraResources(b.extraClosers)
	b.extraClosers = nil
	return errors.Join(handlerErr, objectErr, extraErr)
}

func closeBPFExtraResources(resources []io.Closer) error {
	var closeErr error
	for index, resource := range resources {
		if resource == nil {
			continue
		}
		if err := resource.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close extra BPF resource %d: %w", index, err))
		}
	}
	return closeErr
}
