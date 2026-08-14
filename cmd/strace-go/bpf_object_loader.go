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

func loadBPFObjectBundle(spec *ebpf.CollectionSpec, selection bpfProgramSelection) (*bpfObjectBundle, error) {
	if spec == nil {
		return nil, fmt.Errorf("BPF collection spec is nil")
	}
	if !selection.loadAll {
		spec = spec.Copy()
		if err := pruneBPFProgramSpecs(spec, selection); err != nil {
			return nil, err
		}
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	objects := &bpfObjects{}
	if err := assignBPFCollection(objects, collection); err != nil {
		collection.Close()
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
