package main

import "strace-go/pkg/handler"

type SyscallExitPipeline struct {
	summary     traceSummaryPolicy
	eventPolicy traceEventOutputPolicy
	json        syscallJSONOutputPort
	exit        exitSyscallOutputPort
	runner      syscallHandlerRunnerPort
	text        syscallTextOutputPort
	finalizer   syscallExitFinalizerPort
}

type SyscallExitPipelineDeps struct {
	Summary     traceSummaryPolicy
	EventPolicy traceEventOutputPolicy
	JSON        syscallJSONOutputPort
	Exit        exitSyscallOutputPort
	Runner      syscallHandlerRunnerPort
	Text        syscallTextOutputPort
	Finalizer   syscallExitFinalizerPort
}

// syscallExitFinalizerPort owns side effects that must run after every exit
// pipeline branch, including branches that return before handler decoding.
type syscallExitFinalizerPort interface {
	RecordSummary(syscallEventContext)
	Finalize(syscallEventContext)
}

type traceSessionSyscallExitFinalizer struct {
	summary traceSummaryRecorder
	offsets fdOffsetUpdatePort
	close   fdCloseUpdatePort
}

func newTraceSessionSyscallExitFinalizer(
	summary traceSummaryRecorder,
	offsets fdOffsetUpdatePort,
	close fdCloseUpdatePort,
) *traceSessionSyscallExitFinalizer {
	return &traceSessionSyscallExitFinalizer{
		summary: summary,
		offsets: offsets,
		close:   close,
	}
}

func (f *traceSessionSyscallExitFinalizer) RecordSummary(ev syscallEventContext) {
	if f == nil {
		return
	}
	ev.recordSummary(f.summary)
}

func (f *traceSessionSyscallExitFinalizer) Finalize(ev syscallEventContext) {
	if f != nil {
		if ev.shouldUpdateFDOffsets() {
			ev.updateFDOffsets(f.offsets)
		}
		if ev.shouldCleanupClosedFD() {
			ev.cleanupClosedFD(f.close)
		}
	}
	ev.releaseHandlerContext()
}

func newSyscallExitPipeline(deps SyscallExitPipelineDeps) *SyscallExitPipeline {
	return &SyscallExitPipeline{
		summary:     deps.Summary,
		eventPolicy: deps.EventPolicy,
		json:        deps.JSON,
		exit:        deps.Exit,
		runner:      deps.Runner,
		text:        deps.Text,
		finalizer:   defaultSyscallExitFinalizer(deps.Finalizer),
	}
}

func defaultSyscallExitFinalizer(finalizer syscallExitFinalizerPort) syscallExitFinalizerPort {
	if finalizer != nil {
		return finalizer
	}
	return newTraceSessionSyscallExitFinalizer(nil, nil, nil)
}

func (s *traceSession) syscallExitPipeline() *SyscallExitPipeline {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.exitPipeline
}

// IMPACT: Handle owns the syscall exit/full event pipeline after context construction.
func (p *SyscallExitPipeline) Handle(ev syscallEventContext) {
	if p == nil {
		ev.releaseHandlerContext()
		return
	}
	p.dispatch(ev)
	p.finalizer.Finalize(ev)
}

func (p *SyscallExitPipeline) dispatch(ev syscallEventContext) {
	if p.json != nil && p.json.HandleDebugRaw(ev) {
		return
	}
	if suppressSyscallOutput(ev) {
		return
	}
	if p.recordSummaryIfNeeded(ev) {
		return
	}
	if p.exit != nil && p.exit.Handle(ev) {
		return
	}

	res, shouldOutput := p.handleSyscall(ev)
	if !shouldOutput {
		return
	}
	if p.json != nil && p.json.HandleDecoded(ev, res) {
		return
	}
	if p.text != nil {
		p.text.HandleEvent(ev, res)
	}
}

func (p *SyscallExitPipeline) HandleUnfinished(ev syscallEventContext) bool {
	if p == nil || !p.HasTextOutput() || !p.text.canHandleUnfinished(ev) {
		ev.releaseHandlerContext()
		return false
	}
	res := p.runner.Decode(ev)
	handled := p.text.HandleUnfinished(ev, res)
	ev.releaseHandlerContext()
	return handled
}

func (p *SyscallExitPipeline) HasTextOutput() bool {
	return p != nil && p.text != nil && p.runner != nil
}

func (p *SyscallExitPipeline) recordSummaryIfNeeded(ev syscallEventContext) bool {
	if p.summary == nil || (!p.summary.SummaryOnly() && !p.summary.SummaryAndPrint()) {
		return false
	}
	shouldRecord := ev.shouldOutput()
	if shouldRecord && p.eventPolicy != nil {
		shouldRecord = p.eventPolicy.ShouldEmit(ev, false)
	}
	if shouldRecord && p.finalizer != nil {
		p.finalizer.RecordSummary(ev)
	}
	return p.summary.SummaryOnly()
}

func (p *SyscallExitPipeline) handleSyscall(ev syscallEventContext) (handler.Result, bool) {
	if p.runner == nil {
		return handler.Result{}, false
	}
	return p.runner.Handle(ev)
}

func suppressSyscallOutput(ev syscallEventContext) bool {
	return ev.shouldSuppressOutput()
}
