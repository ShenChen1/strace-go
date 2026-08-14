package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

type recordingTraceCleanupObserver struct {
	steps []traceCleanupTiming
}

func (o *recordingTraceCleanupObserver) RecordCleanupStep(timing traceCleanupTiming) {
	o.steps = append(o.steps, timing)
}

func TestTraceCleanupPlanRunsStepsInReverseOrder(t *testing.T) {
	var order []string
	clock := &fakeTraceClock{monoNs: 100}
	observer := &recordingTraceCleanupObserver{}
	plan := newTraceCleanupPlan(traceCleanupPlanDeps{
		Clock:    clock,
		Observer: observer,
	})

	for _, name := range []string{"bpf_runtime", "ringbuf_reader", "output"} {
		stepName := name
		if err := plan.Add(stepName, func() error {
			order = append(order, stepName)
			clock.monoNs += 10
			return nil
		}); err != nil {
			t.Fatalf("Add(%q) error = %v", name, err)
		}
	}

	if err := plan.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := strings.Join(order, ","), "output,ringbuf_reader,bpf_runtime"; got != want {
		t.Fatalf("cleanup order = %q, want %q", got, want)
	}
	if len(observer.steps) != 3 || observer.steps[0].Name != "output" {
		t.Fatalf("cleanup timings = %+v, want reverse execution order", observer.steps)
	}
	if observer.steps[0].StartNS != 100 || observer.steps[0].EndNS != 110 {
		t.Fatalf("first cleanup timing = %+v, want [100,110]", observer.steps[0])
	}
}

func TestTraceCleanupPlanContinuesAndJoinsErrors(t *testing.T) {
	firstErr := errors.New("output close failed")
	secondErr := errors.New("BPF close failed")
	var order []string
	plan := newTraceCleanupPlan(traceCleanupPlanDeps{})
	if err := plan.Add("bpf_runtime", func() error {
		order = append(order, "bpf_runtime")
		return secondErr
	}); err != nil {
		t.Fatalf("Add(bpf_runtime) error = %v", err)
	}
	if err := plan.Add("output", func() error {
		order = append(order, "output")
		return firstErr
	}); err != nil {
		t.Fatalf("Add(output) error = %v", err)
	}

	err := plan.Close()
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("Close() error = %v, want both cleanup errors", err)
	}
	if got, want := strings.Join(order, ","), "output,bpf_runtime"; got != want {
		t.Fatalf("cleanup order = %q, want %q", got, want)
	}
}

func TestTraceCleanupPlanIsIdempotent(t *testing.T) {
	calls := 0
	plan := newTraceCleanupPlan(traceCleanupPlanDeps{})
	if err := plan.Add("resource", func() error {
		calls++
		return nil
	}); err != nil {
		t.Fatalf("Add(resource) error = %v", err)
	}

	if err := plan.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := plan.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want one", calls)
	}
}

func TestTraceCleanupPhaseWriterEmitsOnlyDebugPhases(t *testing.T) {
	var output bytes.Buffer
	writer := newTraceCleanupPhaseWriter(
		newTraceOutputPolicy(&cli.Options{DebugPhases: true}),
		&output,
	)
	writer.RecordCleanupStep(traceCleanupTiming{
		Name:    "bpf_runtime",
		StartNS: 100,
		EndNS:   145,
	})

	var event jsonPhaseEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode cleanup phase: %v", err)
	}
	if event.Type != "phase" || event.Phase != "cleanup_bpf_runtime" ||
		event.StartTimeNS != 100 || event.TimeNS != 145 || event.DurationNS != 45 {
		t.Fatalf("cleanup phase = %+v, want bpf runtime duration", event)
	}
}

func TestTraceCleanupPlanRejectsInvalidSteps(t *testing.T) {
	plan := newTraceCleanupPlan(traceCleanupPlanDeps{})
	for name, closeFunc := range map[string]func() error{
		"":    func() error { return nil },
		"nil": nil,
	} {
		if err := plan.Add(name, closeFunc); err == nil {
			t.Fatalf("Add(%q) returned nil error", name)
		}
	}
}
