package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestAssignBPFCollectionAllowsOmittedProgramFields(t *testing.T) {
	collection := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"trace_sys_enter": {},
		},
		Maps: completeBPFMapSet(),
	}
	objects := &bpfObjects{}
	if err := assignBPFCollection(objects, collection); err != nil {
		t.Fatalf("assignBPFCollection() error = %v", err)
	}
	if objects.TraceSysEnter == nil {
		t.Fatal("trace_sys_enter was not assigned")
	}
	if objects.EnterNetwork != nil {
		t.Fatal("omitted enter_network was assigned unexpectedly")
	}
}

func TestAssignBPFCollectionRejectsMissingMap(t *testing.T) {
	maps := completeBPFMapSet()
	delete(maps, "events")
	err := assignBPFCollection(&bpfObjects{}, &ebpf.Collection{Maps: maps})
	if err == nil || !strings.Contains(err.Error(), `missing BPF resource "events"`) {
		t.Fatalf("assignBPFCollection() error = %v, want missing events", err)
	}
}

func TestCollectBPFExtraClosersExcludesTaggedResources(t *testing.T) {
	collection := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"trace_sys_enter": {},
			"generated_extra": {},
		},
		Maps: map[string]*ebpf.Map{
			"events":          {},
			".rodata":         {},
			"generated_extra": {},
		},
	}
	closers := collectBPFExtraClosers(collection)
	if len(closers) != 3 {
		t.Fatalf("extra closers = %d, want 3", len(closers))
	}
}

func completeBPFMapSet() map[string]*ebpf.Map {
	maps := make(map[string]*ebpf.Map)
	for name := range taggedBPFResourceNames(reflect.TypeOf(bpfMaps{})) {
		maps[name] = &ebpf.Map{}
	}
	return maps
}
