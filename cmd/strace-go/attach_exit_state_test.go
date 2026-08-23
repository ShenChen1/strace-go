package main

import (
	"errors"
	"testing"
	"time"
)

type fakeTraceAttachExitReader struct {
	exited map[uint32]bool
	err    error
	calls  []uint32
}

func TestTraceAttachStateZeroValueIsSafe(t *testing.T) {
	var owner traceAttachState
	if !owner.targetsDone() {
		t.Fatal("zero-value attach owner reported pending targets")
	}
	if exited, err := owner.targetExitFact(1); err != nil || exited {
		t.Fatalf("zero-value attach exit fact = %v/%v, want false/nil", exited, err)
	}
}

func (r *fakeTraceAttachExitReader) IsExited(pid uint32) (bool, error) {
	r.calls = append(r.calls, pid)
	if r.err != nil {
		return false, r.err
	}
	return r.exited[pid], nil
}

func TestTraceStateRefreshesAttachTargetsFromExitFacts(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{101, 202})
	reader := &fakeTraceAttachExitReader{exited: map[uint32]bool{101: true}}
	state.setAttachExitReader(reader)

	if err := state.RefreshAttachTargets(); err != nil {
		t.Fatalf("RefreshAttachTargets() error = %v", err)
	}
	if _, ok := state.attach.targets[101]; ok {
		t.Fatal("exited attach target 101 was not removed")
	}
	if _, ok := state.attach.targets[202]; !ok {
		t.Fatal("live attach target 202 was removed")
	}
	if len(reader.calls) != 2 {
		t.Fatalf("exit fact lookups = %v, want both attach targets", reader.calls)
	}
}

func TestTraceStateKeepsAttachTargetWhenExitFactReadFails(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{303})
	wantErr := errors.New("attach exit lookup failed")
	state.setAttachExitReader(&fakeTraceAttachExitReader{err: wantErr})

	err := state.RefreshAttachTargets()
	if !errors.Is(err, wantErr) {
		t.Fatalf("RefreshAttachTargets() error = %v, want %v", err, wantErr)
	}
	if state.AttachTargetsDone() {
		t.Fatal("attach target was removed after failed exit fact lookup")
	}
}

func TestTraceStateRejectsConfiguredMissingExitFactReader(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{350})
	state.setAttachExitReader(nil)

	err := state.RefreshAttachTargets()
	if err == nil || !errors.Is(err, errTraceAttachExitReaderUnavailable) {
		t.Fatalf("RefreshAttachTargets() error = %v, want unavailable reader", err)
	}
}

func TestTraceRunStatePropagatesAttachExitFactReadFailure(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{404})
	wantErr := errors.New("BPF attach exit map unavailable")
	state.setAttachExitReader(&fakeTraceAttachExitReader{err: wantErr})
	runState := newTraceRunState(traceRunStateDeps{
		attachPids:  []int{404},
		attachState: state,
		clock:       &fakeTraceClock{now: time.Unix(100, 0)},
	})

	err := runState.collect(nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("collect() error = %v, want %v", err, wantErr)
	}
	if runState.attachExited {
		t.Fatal("run state finished after attach exit fact read failure")
	}
}
