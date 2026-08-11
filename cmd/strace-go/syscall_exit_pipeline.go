package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type SyscallExitPipeline struct {
	opts    *cli.Options
	json    syscallJSONOutputPort
	exit    exitSyscallOutputPort
	runner  syscallHandlerRunnerPort
	text    syscallTextOutputPort
	effects SyscallExitEffects
}

type SyscallExitPipelineDeps struct {
	Opts    *cli.Options
	JSON    syscallJSONOutputPort
	Exit    exitSyscallOutputPort
	Runner  syscallHandlerRunnerPort
	Text    syscallTextOutputPort
	Effects SyscallExitEffects
}

type SyscallExitEffects interface {
	RecordSummary(syscallEventContext)
	UpdateFDOffsets(syscallEventContext)
	CleanupClosedFD(syscallEventContext)
}

type traceSessionSyscallExitEffects struct {
	summary *SummaryStats
	offsets fdOffsetUpdatePort
	close   fdCloseUpdatePort
}

func newTraceSessionSyscallExitEffects(
	summary *SummaryStats,
	offsets fdOffsetUpdatePort,
	close fdCloseUpdatePort,
) *traceSessionSyscallExitEffects {
	return &traceSessionSyscallExitEffects{
		summary: summary,
		offsets: offsets,
		close:   close,
	}
}

func (e *traceSessionSyscallExitEffects) RecordSummary(ev syscallEventContext) {
	ev.recordSummary(e.summary)
}

func (e *traceSessionSyscallExitEffects) UpdateFDOffsets(ev syscallEventContext) {
	ev.updateFDOffsets(e.offsets)
}

func (e *traceSessionSyscallExitEffects) CleanupClosedFD(ev syscallEventContext) {
	ev.cleanupClosedFD(e.close)
}

func newSyscallExitPipeline(deps SyscallExitPipelineDeps) *SyscallExitPipeline {
	return &SyscallExitPipeline{
		opts:    deps.Opts,
		json:    deps.JSON,
		exit:    deps.Exit,
		runner:  deps.Runner,
		text:    deps.Text,
		effects: deps.Effects,
	}
}

func (s *traceSession) syscallExitPipeline() *SyscallExitPipeline {
	components := s.componentsOrBuild()
	if components == nil {
		return nil
	}
	return components.exitPipeline
}

// IMPACT: Handle owns the syscall exit/full event pipeline after context construction.
func (p *SyscallExitPipeline) Handle(ev syscallEventContext) {
	defer p.cleanup(ev)
	defer p.updateOffsets(ev)

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
	if !p.HasTextOutput() || !p.text.canHandleUnfinished(ev) {
		return false
	}
	res := p.runner.Decode(ev)
	return p.text.HandleUnfinished(ev, res)
}

func (p *SyscallExitPipeline) HasTextOutput() bool {
	return p != nil && p.text != nil && p.runner != nil
}

func (p *SyscallExitPipeline) recordSummaryIfNeeded(ev syscallEventContext) bool {
	if p.opts == nil || (!p.opts.SummaryOnly && !p.opts.SummaryAndPrint) {
		return false
	}
	if p.effects != nil {
		p.effects.RecordSummary(ev)
	}
	return p.opts.SummaryOnly
}

func (p *SyscallExitPipeline) handleSyscall(ev syscallEventContext) (handler.Result, bool) {
	if p.runner == nil {
		return handler.Result{}, false
	}
	return p.runner.Handle(ev)
}

func (p *SyscallExitPipeline) cleanup(ev syscallEventContext) {
	if p.effects != nil {
		p.effects.CleanupClosedFD(ev)
	}
}

func (p *SyscallExitPipeline) updateOffsets(ev syscallEventContext) {
	if p.effects != nil {
		p.effects.UpdateFDOffsets(ev)
	}
}

func suppressSyscallOutput(ev syscallEventContext) bool {
	return ev.shouldSuppressOutput()
}
