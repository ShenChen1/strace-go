package main

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeBPFObjectLoader struct {
	calls      []string
	loaded     *bpfLoadedCollection
	bindBundle *bpfObjectBundle
	prepareErr error
	loadErr    error
	bindErr    error
}

func (l *fakeBPFObjectLoader) prepare(
	spec *ebpf.CollectionSpec,
	selection bpfProgramSelection,
) (*bpfCollectionPlan, error) {
	l.calls = append(l.calls, "prepare")
	if l.prepareErr != nil {
		return nil, l.prepareErr
	}
	return &bpfCollectionPlan{spec: spec, selection: selection}, nil
}

func (l *fakeBPFObjectLoader) load(plan *bpfCollectionPlan) (*bpfLoadedCollection, error) {
	l.calls = append(l.calls, "load")
	return l.loaded, l.loadErr
}

func (l *fakeBPFObjectLoader) bind(loaded *bpfLoadedCollection) (*bpfObjectBundle, error) {
	l.calls = append(l.calls, "bind")
	if l.bindErr != nil {
		return nil, l.bindErr
	}
	return l.bindBundle, nil
}

type countingBPFCloser struct {
	calls int
}

func (c *countingBPFCloser) Close() error {
	c.calls++
	return nil
}

func TestBPFObjectPipelineClosesLoadedCollectionOnBindFailure(t *testing.T) {
	wantErr := errors.New("bind failed")
	closer := &countingBPFCloser{}
	observer := newBPFSetupRecorder()
	loader := &fakeBPFObjectLoader{
		loaded:  &bpfLoadedCollection{closer: closer},
		bindErr: wantErr,
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4, 5, 6}},
		observer,
		&ebpf.CollectionSpec{},
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("loadBPFObjectsWithTiming() error = %v, want %v", err, wantErr)
	}
	if closer.calls != 1 {
		t.Fatalf("loaded collection close calls = %d, want 1", closer.calls)
	}
	if err := loader.loaded.Close(); err != nil {
		t.Fatalf("second loaded collection close = %v, want nil", err)
	}
	if closer.calls != 1 {
		t.Fatalf("loaded collection close calls after second close = %d, want 1", closer.calls)
	}
	if got, want := loader.calls, []string{"prepare", "load", "bind"}; !equalStringSlices(got, want) {
		t.Fatalf("loader calls = %v, want %v", got, want)
	}
	if got, want := bpfSetupStages(observer.Timings()), []traceBPFSetupStage{
		bpfSetupObjectPrepareStage,
		bpfSetupCollectionLoadStage,
		bpfSetupResourceBindStage,
	}; !equalSetupStages(got, want) {
		t.Fatalf("recorded object stages = %v, want %v", got, want)
	}
}

func TestBPFObjectPipelineDetachesAfterSuccessfulBind(t *testing.T) {
	closer := &countingBPFCloser{}
	loaded := &bpfLoadedCollection{closer: closer}
	loader := &fakeBPFObjectLoader{
		loaded:     loaded,
		bindBundle: &bpfObjectBundle{},
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4, 5, 6}},
		newBPFSetupRecorder(),
		&ebpf.CollectionSpec{},
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if err != nil {
		t.Fatalf("loadBPFObjectsWithTiming() error = %v, want nil", err)
	}
	if closer.calls != 0 {
		t.Fatalf("detached collection close calls = %d, want 0", closer.calls)
	}
	if !loaded.detached {
		t.Fatal("loaded collection was not detached after successful bind")
	}
	if err := loaded.Close(); err != nil {
		t.Fatalf("detached collection close = %v, want nil", err)
	}
}

func TestBPFObjectPipelineClosesPartialCollectionOnLoadFailure(t *testing.T) {
	closer := &countingBPFCloser{}
	loader := &fakeBPFObjectLoader{
		loaded:  &bpfLoadedCollection{closer: closer},
		loadErr: errors.New("load failed"),
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4}},
		newBPFSetupRecorder(),
		&ebpf.CollectionSpec{},
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if err == nil || !errors.Is(err, loader.loadErr) {
		t.Fatalf("load failure = %v, want %v", err, loader.loadErr)
	}
	if closer.calls != 1 {
		t.Fatalf("partial collection close calls = %d, want 1", closer.calls)
	}
	if len(loader.calls) != 2 || loader.calls[1] != "load" {
		t.Fatalf("loader calls after load failure = %v, want prepare/load", loader.calls)
	}
}

func TestNativeBPFObjectLoaderPrepareCopiesSelectiveSpec(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"keep":   {},
			"remove": {},
		},
	}
	loader := &nativeBPFObjectLoader{}
	plan, err := loader.prepare(spec, bpfProgramSelection{
		programs: map[string]struct{}{"keep": {}},
	})
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if _, ok := spec.Programs["remove"]; !ok {
		t.Fatal("prepare() mutated the caller's collection spec")
	}
	if _, ok := plan.spec.Programs["remove"]; ok {
		t.Fatal("prepare() kept an unselected program")
	}
}

func TestNativeBPFObjectLoaderRejectsMissingSpec(t *testing.T) {
	_, err := (&nativeBPFObjectLoader{}).prepare(nil, bpfProgramSelection{loadAll: true})
	if err == nil || err.Error() != "BPF collection spec is nil" {
		t.Fatalf("prepare(nil) error = %v, want missing spec error", err)
	}
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func bpfSetupStages(timings []traceBPFSetupTiming) []traceBPFSetupStage {
	stages := make([]traceBPFSetupStage, 0, len(timings))
	for _, timing := range timings {
		stages = append(stages, timing.Stage)
	}
	return stages
}

func equalSetupStages(got, want []traceBPFSetupStage) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
