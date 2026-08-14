package main

import (
	"errors"
	"testing"
	"time"
)

type fakeBPFSetupObserver struct {
	timings []traceBPFSetupTiming
}

func (o *fakeBPFSetupObserver) RecordBPFSetupStage(timing traceBPFSetupTiming) {
	o.timings = append(o.timings, timing)
}

type sequenceBPFSetupClock struct {
	values []uint64
	index  int
}

func (c *sequenceBPFSetupClock) NowMonoNs() uint64 {
	value := c.values[c.index]
	c.index++
	return value
}

func (c *sequenceBPFSetupClock) Now() time.Time {
	return time.Unix(0, int64(c.values[0]))
}

func TestMeasureBPFSetupStageRecordsTimingOnFailure(t *testing.T) {
	wantErr := errors.New("load failed")
	observer := &fakeBPFSetupObserver{}
	clock := &sequenceBPFSetupClock{values: []uint64{10, 25}}

	err := measureBPFSetupStage(clock, observer, bpfSetupObjectsStage, func() error {
		return wantErr
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("measureBPFSetupStage() error = %v, want %v", err, wantErr)
	}
	if len(observer.timings) != 1 {
		t.Fatalf("recorded timings = %d, want 1", len(observer.timings))
	}
	got := observer.timings[0]
	if got.Stage != bpfSetupObjectsStage || got.StartNS != 10 || got.EndNS != 25 {
		t.Fatalf("timing = %+v, want stage objects [10,25]", got)
	}
}

func TestBPFSetupRecorderReturnsIndependentTimingSnapshot(t *testing.T) {
	recorder := newBPFSetupRecorder()
	clock := &sequenceBPFSetupClock{values: []uint64{1, 2}}
	if err := measureBPFSetupStage(clock, recorder, bpfSetupSpecStage, func() error { return nil }); err != nil {
		t.Fatalf("measureBPFSetupStage() error = %v", err)
	}

	timings := recorder.Timings()
	if len(timings) != 1 {
		t.Fatalf("timings = %d, want 1", len(timings))
	}
	timings[0].Stage = "mutated"
	if recorder.Timings()[0].Stage != bpfSetupSpecStage {
		t.Fatal("recorder exposed mutable timing storage")
	}
}
