package main

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type fixedBPFSetupClock struct{}

func (fixedBPFSetupClock) Now() time.Time {
	return time.Unix(0, 100)
}

func (fixedBPFSetupClock) NowMonoNs() uint64 {
	return 100
}

func TestLoadBPFHandlerCollectionsParallelKeepsFamilyOrder(t *testing.T) {
	plan := &bpfCollectionPlan{
		handlerSpecs: map[bpfHandlerFamily]*ebpf.CollectionSpec{
			bpfHandlerEnterGenericFamily: {Programs: map[string]*ebpf.ProgramSpec{"generic": {}}},
			bpfHandlerEnterPayloadFamily: {Programs: map[string]*ebpf.ProgramSpec{"payload": {}}},
			bpfHandlerExitFamily:         {Programs: map[string]*ebpf.ProgramSpec{"exit": {}}},
		},
	}
	load := func(family bpfHandlerFamily, spec *ebpf.CollectionSpec, core *ebpf.Collection) (*bpfLoadedCollection, error) {
		return &bpfLoadedCollection{collection: &ebpf.Collection{}, closer: &countingBPFCloser{}}, nil
	}

	loaded, timings, err := loadBPFHandlerCollectionsParallel(
		plan,
		&ebpf.Collection{},
		fixedBPFSetupClock{},
		load,
	)
	if err != nil {
		t.Fatalf("loadBPFHandlerCollectionsParallel() error = %v", err)
	}
	if got, want := loaded.loadOrder, []bpfHandlerFamily{
		bpfHandlerEnterGenericFamily,
		bpfHandlerEnterPayloadFamily,
		bpfHandlerExitFamily,
	}; !equalHandlerFamilies(got, want) {
		t.Fatalf("loaded family order = %v, want %v", got, want)
	}
	if len(timings) != len(bpfHandlerFamilyCatalog) {
		t.Fatalf("timing count = %d, want %d", len(timings), len(bpfHandlerFamilyCatalog))
	}
	for index, familySpec := range bpfHandlerFamilyCatalog {
		if got, want := timings[index].Stage, familySpec.stage; got != want {
			t.Fatalf("timing %d stage = %q, want %q", index, got, want)
		}
	}
}

func TestLoadBPFHandlerCollectionsParallelReturnsCompletedLoadsOnFailure(t *testing.T) {
	wantErr := errors.New("payload load failed")
	genericCloser := &countingBPFCloser{}
	plan := &bpfCollectionPlan{
		handlerSpecs: map[bpfHandlerFamily]*ebpf.CollectionSpec{
			bpfHandlerEnterGenericFamily: {Programs: map[string]*ebpf.ProgramSpec{"generic": {}}},
			bpfHandlerEnterPayloadFamily: {Programs: map[string]*ebpf.ProgramSpec{"payload": {}}},
		},
	}
	load := func(family bpfHandlerFamily, spec *ebpf.CollectionSpec, core *ebpf.Collection) (*bpfLoadedCollection, error) {
		if family == bpfHandlerEnterPayloadFamily {
			return nil, wantErr
		}
		return &bpfLoadedCollection{collection: &ebpf.Collection{}, closer: genericCloser}, nil
	}

	loaded, _, err := loadBPFHandlerCollectionsParallel(
		plan,
		&ebpf.Collection{},
		fixedBPFSetupClock{},
		load,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("load error = %v, want %v", err, wantErr)
	}
	if loaded == nil {
		t.Fatal("loaded handler owner is nil after a partial failure")
	}
	if closeErr := loaded.Close(); closeErr != nil {
		t.Fatalf("loaded.Close() error = %v", closeErr)
	}
	if genericCloser.calls != 1 {
		t.Fatalf("completed collection close calls = %d, want 1", genericCloser.calls)
	}
}

func TestBPFLoadedHandlerCollectionsTransferKeepsResourceNames(t *testing.T) {
	loaded := &bpfLoadedHandlerCollections{
		collections: map[bpfHandlerFamily]*bpfLoadedCollection{
			bpfHandlerEnterGenericFamily: {closer: &countingBPFCloser{}},
			bpfHandlerExitFamily:         {closer: &countingBPFCloser{}},
		},
		loadOrder: []bpfHandlerFamily{bpfHandlerEnterGenericFamily, bpfHandlerExitFamily},
	}
	bundle := &bpfObjectBundle{}
	loaded.transferTo(bundle)
	if got, want := len(bundle.handlerResources.resources), 2; got != want {
		t.Fatalf("transferred resources = %d, want %d", got, want)
	}
	if got, want := bundle.handlerResources.resources[0].Name, "bpf_handler_0"; got != want {
		t.Fatalf("first handler resource name = %q, want %q", got, want)
	}
	if got, want := bundle.handlerResources.resources[1].Name, "bpf_handler_1"; got != want {
		t.Fatalf("second handler resource name = %q, want %q", got, want)
	}
}
