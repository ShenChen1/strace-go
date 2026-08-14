package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type traceCleanupTiming struct {
	Name    string
	StartNS uint64
	EndNS   uint64
}

type traceCleanupObserver interface {
	RecordCleanupStep(traceCleanupTiming)
}

type traceCleanupStep struct {
	name  string
	close func() error
}

type traceCleanupPlanDeps struct {
	Clock    traceClock
	Observer traceCleanupObserver
}

// traceCleanupPlan is the single owner for resources acquired by the launch
// boundary. Steps close in reverse registration order and retain every error.
type traceCleanupPlan struct {
	clock    traceClock
	observer traceCleanupObserver
	steps    []traceCleanupStep
	closed   bool
}

func newTraceCleanupPlan(deps traceCleanupPlanDeps) *traceCleanupPlan {
	return &traceCleanupPlan{
		clock:    deps.Clock,
		observer: deps.Observer,
	}
}

func (p *traceCleanupPlan) Add(name string, closeFunc func() error) error {
	if p == nil {
		return fmt.Errorf("trace cleanup plan is nil")
	}
	if p.closed {
		return fmt.Errorf("trace cleanup plan is already closed")
	}
	if name == "" {
		return fmt.Errorf("trace cleanup step name is empty")
	}
	if closeFunc == nil {
		return fmt.Errorf("trace cleanup step %q has no closer", name)
	}
	p.steps = append(p.steps, traceCleanupStep{name: name, close: closeFunc})
	return nil
}

func (p *traceCleanupPlan) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	steps := p.steps
	p.steps = nil
	var closeErr error
	for index := len(steps) - 1; index >= 0; index-- {
		step := steps[index]
		startNS := p.nowMonoNS()
		err := step.close()
		endNS := p.nowMonoNS()
		p.recordTiming(traceCleanupTiming{Name: step.name, StartNS: startNS, EndNS: endNS})
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("cleanup %s: %w", step.name, err))
		}
	}
	return closeErr
}

func (p *traceCleanupPlan) nowMonoNS() uint64 {
	if p == nil || p.clock == nil {
		return 0
	}
	return p.clock.NowMonoNs()
}

func (p *traceCleanupPlan) recordTiming(timing traceCleanupTiming) {
	if p != nil && p.observer != nil {
		p.observer.RecordCleanupStep(timing)
	}
}

// traceCleanupPhaseWriter keeps post-output cleanup observable without
// reopening or writing to the session-owned trace output.
type traceCleanupPhaseWriter struct {
	encoder *json.Encoder
}

func newTraceCleanupPhaseWriter(policy traceReadyPolicy, output io.Writer) *traceCleanupPhaseWriter {
	if policy == nil || !policy.DebugPhases() || output == nil {
		return nil
	}
	return &traceCleanupPhaseWriter{encoder: json.NewEncoder(output)}
}

func (w *traceCleanupPhaseWriter) RecordCleanupStep(timing traceCleanupTiming) {
	if w == nil || w.encoder == nil {
		return
	}
	_ = w.encoder.Encode(newJSONPhaseEventAt(
		"cleanup_"+timing.Name,
		timing.StartNS,
		timing.EndNS,
	))
}
