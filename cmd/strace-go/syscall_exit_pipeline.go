package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type SyscallExitPipeline struct {
	opts            *cli.Options
	json            *SyscallJSONOutput
	exit            *ExitSyscallOutput
	runner          *SyscallHandlerRunner
	text            *SyscallTextOutput
	recordSummary   func(syscallEventContext)
	cleanupClosedFD func(syscallEventContext)
	updateFDOffsets func(syscallEventContext)
}

type SyscallExitPipelineDeps struct {
	Opts            *cli.Options
	JSON            *SyscallJSONOutput
	Exit            *ExitSyscallOutput
	Runner          *SyscallHandlerRunner
	Text            *SyscallTextOutput
	RecordSummary   func(syscallEventContext)
	CleanupClosedFD func(syscallEventContext)
	UpdateFDOffsets func(syscallEventContext)
}

func newSyscallExitPipeline(deps SyscallExitPipelineDeps) *SyscallExitPipeline {
	return &SyscallExitPipeline{
		opts:            deps.Opts,
		json:            deps.JSON,
		exit:            deps.Exit,
		runner:          deps.Runner,
		text:            deps.Text,
		recordSummary:   deps.RecordSummary,
		cleanupClosedFD: deps.CleanupClosedFD,
		updateFDOffsets: deps.UpdateFDOffsets,
	}
}

func (s *traceSession) syscallExitPipeline() *SyscallExitPipeline {
	return newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:            s.opts,
		JSON:            s.syscallJSONOutput(),
		Exit:            s.exitSyscallOutput(),
		Runner:          s.syscallHandlerRunner(),
		Text:            s.syscallTextOutput(),
		RecordSummary:   s.updateSummaryStats,
		CleanupClosedFD: s.cleanupClosedFD,
		UpdateFDOffsets: s.updateSyscallFDOffsets,
	})
}

// IMPACT: Handle owns the syscall exit/full event pipeline after context construction.
func (p *SyscallExitPipeline) Handle(ev syscallEventContext) {
	defer p.cleanup(ev)
	defer p.updateOffsets(ev)

	if p.json != nil && p.json.HandleDebugRaw(ev.raw, ev.meta) {
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
		p.text.Handle(ev.handlerContext, ev.raw, res)
	}
}

func (p *SyscallExitPipeline) recordSummaryIfNeeded(ev syscallEventContext) bool {
	if p.opts == nil || (!p.opts.SummaryOnly && !p.opts.SummaryAndPrint) {
		return false
	}
	if p.recordSummary != nil {
		p.recordSummary(ev)
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
	if p.cleanupClosedFD != nil {
		p.cleanupClosedFD(ev)
	}
}

func (p *SyscallExitPipeline) updateOffsets(ev syscallEventContext) {
	if p.updateFDOffsets != nil {
		p.updateFDOffsets(ev)
	}
}

func suppressSyscallOutput(ev syscallEventContext) bool {
	return ev.meta.Name == "arch_prctl" && ev.raw.Args[0] == 0x1002
}
