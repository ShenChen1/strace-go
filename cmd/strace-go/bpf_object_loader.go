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
	objects      *bpfObjects
	extraClosers []io.Closer
}

// bpfCollectionPlan owns the prepared spec until a collection is loaded.
// Keeping selection beside the spec prevents a loader backend from silently
// loading a different program set than the route plan requested.
type bpfCollectionPlan struct {
	spec      *ebpf.CollectionSpec
	selection bpfProgramSelection
}

// bpfLoadedCollection is the temporary owner between kernel collection load
// and generated-resource binding. detach transfers every live handle to the
// resulting bpfObjectBundle.
type bpfLoadedCollection struct {
	collection *ebpf.Collection
	closer     io.Closer
	closed     bool
	detached   bool
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

// bpfObjectLoader is the ownership boundary between setup orchestration and
// a concrete collection backend. A future family loader can implement the
// same plan/load/bind lifecycle without leaking generated objects upward.
type bpfObjectLoader interface {
	prepare(*ebpf.CollectionSpec, bpfProgramSelection) (*bpfCollectionPlan, error)
	load(*bpfCollectionPlan) (*bpfLoadedCollection, error)
	bind(*bpfLoadedCollection) (*bpfObjectBundle, error)
}

type nativeBPFObjectLoader struct{}

func (l *nativeBPFObjectLoader) prepare(
	spec *ebpf.CollectionSpec,
	selection bpfProgramSelection,
) (*bpfCollectionPlan, error) {
	if spec == nil {
		return nil, fmt.Errorf("BPF collection spec is nil")
	}
	prepared := spec
	if !selection.loadAll {
		prepared = spec.Copy()
		if err := pruneBPFProgramSpecs(prepared, selection); err != nil {
			return nil, fmt.Errorf("prepare selected BPF programs: %w", err)
		}
	}
	return &bpfCollectionPlan{spec: prepared, selection: selection}, nil
}

func (l *nativeBPFObjectLoader) load(plan *bpfCollectionPlan) (*bpfLoadedCollection, error) {
	if plan == nil || plan.spec == nil {
		return nil, fmt.Errorf("BPF collection plan is unavailable")
	}
	collection, err := ebpf.NewCollection(plan.spec)
	if err != nil {
		return nil, err
	}
	return &bpfLoadedCollection{collection: collection}, nil
}

func (l *nativeBPFObjectLoader) bind(loaded *bpfLoadedCollection) (*bpfObjectBundle, error) {
	collection := loaded.value()
	if collection == nil {
		return nil, fmt.Errorf("loaded BPF collection is unavailable")
	}
	objects := &bpfObjects{}
	if err := assignBPFCollection(objects, collection); err != nil {
		return nil, err
	}
	extraClosers := collectBPFExtraClosers(collection)
	return &bpfObjectBundle{objects: objects, extraClosers: extraClosers}, nil
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

func (b *bpfObjectBundle) Close() error {
	if b == nil {
		return nil
	}
	var objectErr error
	if b.objects != nil {
		objectErr = b.objects.Close()
		b.objects = nil
	}
	extraErr := closeBPFExtraResources(b.extraClosers)
	b.extraClosers = nil
	return errors.Join(objectErr, extraErr)
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
