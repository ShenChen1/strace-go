package main

import "strace-go/pkg/cli"

// traceFormatPolicy exposes only the output format decision.
type traceFormatPolicy interface {
	IsJSON() bool
}

// traceEventOutputPolicy owns debug and status decisions for syscall events.
// unfinished distinguishes an enter-side text fragment from a completed exit.
type traceEventOutputPolicy interface {
	DebugEvents() bool
	ShouldEmit(ev syscallEventContext, unfinished bool) bool
}

// traceSummaryPolicy controls summary-only and summary-plus-output modes.
type traceSummaryPolicy interface {
	SummaryOnly() bool
	SummaryAndPrint() bool
}

// traceExitPolicy controls command and exit-syscall fallback output.
type traceExitPolicy interface {
	IsJSON() bool
	SummaryOnly() bool
	QuietExit() bool
}

// cliTraceOutputPolicy is a session-scoped immutable snapshot of output policy.
type cliTraceOutputPolicy struct {
	json               bool
	debug              bool
	status             successfulFailedOptions
	statusFilterActive bool
	summaryOnly        bool
	summaryAndPrint    bool
	quietExit          bool
}

var (
	_ traceFormatPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceEventOutputPolicy = (*cliTraceOutputPolicy)(nil)
	_ traceSummaryPolicy     = (*cliTraceOutputPolicy)(nil)
	_ traceExitPolicy        = (*cliTraceOutputPolicy)(nil)
)

func newTraceOutputPolicy(opts *cli.Options) *cliTraceOutputPolicy {
	if opts == nil {
		return nil
	}
	traceStatus := make(map[string]bool, len(opts.TraceStatus))
	for name, enabled := range opts.TraceStatus {
		traceStatus[name] = enabled
	}
	return &cliTraceOutputPolicy{
		json:               opts.EventFormat == cli.EventFormatJSON,
		debug:              opts.DebugEvents,
		status:             successfulFailedOptions{successfulOnly: opts.SuccessfulOnly, failedOnly: opts.FailedOnly, traceStatus: traceStatus},
		statusFilterActive: opts.SuccessfulOnly || opts.FailedOnly || len(traceStatus) > 0,
		summaryOnly:        opts.SummaryOnly,
		summaryAndPrint:    opts.SummaryAndPrint,
		quietExit:          opts.QuietExit,
	}
}

func (p *cliTraceOutputPolicy) IsJSON() bool {
	return p != nil && p.json
}

func (p *cliTraceOutputPolicy) DebugEvents() bool {
	return p != nil && p.debug
}

func (p *cliTraceOutputPolicy) ShouldEmit(ev syscallEventContext, unfinished bool) bool {
	if p == nil {
		return true
	}
	if unfinished {
		return !p.statusFilterActive
	}
	return ev.shouldEmitStatus(p.status)
}

func (p *cliTraceOutputPolicy) SummaryOnly() bool {
	return p != nil && p.summaryOnly
}

func (p *cliTraceOutputPolicy) SummaryAndPrint() bool {
	return p != nil && p.summaryAndPrint
}

func (p *cliTraceOutputPolicy) QuietExit() bool {
	return p != nil && p.quietExit
}
