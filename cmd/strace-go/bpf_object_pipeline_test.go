package main

import (
	"errors"
	"io"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeBPFObjectLoader struct {
	calls          []string
	loadedCore     *bpfLoadedCollection
	loadedHandlers *bpfLoadedHandlerCollections
	bindBundle     *bpfObjectBundle
	prepareErr     error
	coreLoadErr    error
	handlerLoadErr error
	bindErr        error
}

func (l *fakeBPFObjectLoader) prepare(
	specs *bpfCollectionSpecSet,
	selection bpfProgramSelection,
) (*bpfCollectionPlan, error) {
	l.calls = append(l.calls, "prepare")
	if l.prepareErr != nil {
		return nil, l.prepareErr
	}
	return &bpfCollectionPlan{
		coreSpec:     specs.core,
		handlerSpecs: specs.handlers,
		selection:    selection,
	}, nil
}

func (l *fakeBPFObjectLoader) loadCore(plan *bpfCollectionPlan) (*bpfLoadedCollection, error) {
	l.calls = append(l.calls, "load_core")
	return l.loadedCore, l.coreLoadErr
}

func (l *fakeBPFObjectLoader) loadHandlers(
	plan *bpfCollectionPlan,
	core *bpfLoadedCollection,
	clock traceClock,
	observer traceBPFSetupObserver,
) (*bpfLoadedHandlerCollections, error) {
	l.calls = append(l.calls, "load_handlers")
	aggregateRecorder := newBPFSetupRecorder()
	childRecorder := newBPFSetupRecorder()
	err := measureBPFSetupStage(clock, aggregateRecorder, bpfSetupHandlerCollectionsStage, func() error {
		for _, familySpec := range bpfHandlerFamilyCatalog {
			if err := measureBPFSetupStage(clock, childRecorder, familySpec.stage, func() error {
				return nil
			}); err != nil {
				return err
			}
		}
		return l.handlerLoadErr
	})
	if observer != nil {
		for _, timing := range aggregateRecorder.Timings() {
			observer.RecordBPFSetupStage(timing)
		}
		for _, timing := range childRecorder.Timings() {
			observer.RecordBPFSetupStage(timing)
		}
	}
	return l.loadedHandlers, err
}

func (l *fakeBPFObjectLoader) bind(loaded *bpfLoadedCollectionSet) (*bpfObjectBundle, error) {
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
		loadedCore:     &bpfLoadedCollection{closer: closer},
		loadedHandlers: testLoadedHandlerCollections(&countingBPFCloser{}),
		bindErr:        wantErr,
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}},
		observer,
		testBPFCollectionSpecSet(),
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("loadBPFObjectsWithTiming() error = %v, want %v", err, wantErr)
	}
	if closer.calls != 1 {
		t.Fatalf("loaded collection close calls = %d, want 1", closer.calls)
	}
	if err := loader.loadedCore.Close(); err != nil {
		t.Fatalf("second loaded collection close = %v, want nil", err)
	}
	if closer.calls != 1 {
		t.Fatalf("loaded collection close calls after second close = %d, want 1", closer.calls)
	}
	if got, want := loader.calls, []string{"prepare", "load_core", "load_handlers", "bind"}; !equalStringSlices(got, want) {
		t.Fatalf("loader calls = %v, want %v", got, want)
	}
	if got, want := bpfSetupStages(observer.Timings()), []traceBPFSetupStage{
		bpfSetupObjectPrepareStage,
		bpfSetupCoreCollectionStage,
		bpfSetupHandlerCollectionsStage,
		bpfSetupEnterGenericCollectionStage,
		bpfSetupEnterPayloadCollectionStage,
		bpfSetupEnterPathCollectionStage,
		bpfSetupEnterMemoryCollectionStage,
		bpfSetupEnterControlCollectionStage,
		bpfSetupEnterStructuredCollectionStage,
		bpfSetupExitCollectionStage,
		bpfSetupRecvmsgCollectionStage,
		bpfSetupResourceBindStage,
	}; !equalSetupStages(got, want) {
		t.Fatalf("recorded object stages = %v, want %v", got, want)
	}
}

func TestBPFObjectPipelineDetachesAfterSuccessfulBind(t *testing.T) {
	closer := &countingBPFCloser{}
	loadedCore := &bpfLoadedCollection{closer: closer}
	handlerCloser := &countingBPFCloser{}
	loader := &fakeBPFObjectLoader{
		loadedCore:     loadedCore,
		loadedHandlers: testLoadedHandlerCollections(handlerCloser),
		bindBundle:     &bpfObjectBundle{},
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}},
		newBPFSetupRecorder(),
		testBPFCollectionSpecSet(),
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if err != nil {
		t.Fatalf("loadBPFObjectsWithTiming() error = %v, want nil", err)
	}
	if closer.calls != 0 {
		t.Fatalf("detached collection close calls = %d, want 0", closer.calls)
	}
	if !loadedCore.detached {
		t.Fatal("core collection was not detached after successful bind")
	}
	if err := loadedCore.Close(); err != nil {
		t.Fatalf("detached core collection close = %v, want nil", err)
	}
	if handlerCloser.calls != 0 {
		t.Fatalf("handler collection close calls = %d, want 0 before bundle close", handlerCloser.calls)
	}
}

func TestBPFObjectPipelineClosesPartialCollectionOnLoadFailure(t *testing.T) {
	closer := &countingBPFCloser{}
	loader := &fakeBPFObjectLoader{
		loadedCore:  &bpfLoadedCollection{closer: closer},
		coreLoadErr: errors.New("load failed"),
	}

	_, err := loadBPFObjectsWithTiming(
		&sequenceBPFSetupClock{values: []uint64{1, 2, 3, 4}},
		newBPFSetupRecorder(),
		testBPFCollectionSpecSet(),
		bpfProgramSelection{loadAll: true},
		loader,
	)
	if err == nil || !errors.Is(err, loader.coreLoadErr) {
		t.Fatalf("load failure = %v, want %v", err, loader.coreLoadErr)
	}
	if closer.calls != 1 {
		t.Fatalf("partial collection close calls = %d, want 1", closer.calls)
	}
	if len(loader.calls) != 2 || loader.calls[1] != "load_core" {
		t.Fatalf("loader calls after load failure = %v, want prepare/load_core", loader.calls)
	}
}

func TestNativeBPFObjectLoaderPrepareCopiesSelectiveSpec(t *testing.T) {
	coreSpec := &ebpf.CollectionSpec{}
	handlerSpec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"enter_no_payload_generic": {},
			"enter_terminating":        {},
		},
	}
	loader := &nativeBPFObjectLoader{}
	plan, err := loader.prepare(&bpfCollectionSpecSet{
		core: coreSpec,
		handlers: map[bpfHandlerFamily]*ebpf.CollectionSpec{
			bpfHandlerEnterGenericFamily: handlerSpec,
		},
	}, bpfProgramSelection{
		programs: map[string]struct{}{"enter_no_payload_generic": {}},
	})
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if _, ok := handlerSpec.Programs["enter_terminating"]; !ok {
		t.Fatal("prepare() mutated the caller's collection spec")
	}
	if _, ok := plan.handlerSpecs[bpfHandlerEnterGenericFamily].Programs["enter_terminating"]; ok {
		t.Fatal("prepare() kept an unselected program")
	}
}

func TestNativeBPFObjectLoaderRejectsMissingSpec(t *testing.T) {
	_, err := (&nativeBPFObjectLoader{}).prepare(nil, bpfProgramSelection{loadAll: true})
	if err == nil || err.Error() != "BPF core and handler specs are required" {
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

func testBPFCollectionSpecSet() *bpfCollectionSpecSet {
	return &bpfCollectionSpecSet{
		core: &ebpf.CollectionSpec{},
		handlers: map[bpfHandlerFamily]*ebpf.CollectionSpec{
			bpfHandlerEnterGenericFamily: &ebpf.CollectionSpec{},
			bpfHandlerExitFamily:         &ebpf.CollectionSpec{},
			bpfHandlerRecvmsgFamily:      &ebpf.CollectionSpec{},
		},
	}
}

func testLoadedHandlerCollections(closer io.Closer) *bpfLoadedHandlerCollections {
	return &bpfLoadedHandlerCollections{
		collections: map[bpfHandlerFamily]*bpfLoadedCollection{
			bpfHandlerEnterGenericFamily: {closer: closer},
		},
		loadOrder: []bpfHandlerFamily{bpfHandlerEnterGenericFamily},
	}
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
