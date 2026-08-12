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

type traceTimeOptions struct {
	printTimeMode     int
	printRelativeTime bool
}

type traceRenderOptions struct {
	time              traceTimeOptions
	followForks       bool
	alignCol          int
	printSyscallTime  bool
	stackTrace        bool
	quietThreadExecve bool
}

// traceRenderPolicy exposes the immutable scalar options used by text output.
type traceRenderPolicy interface {
	RenderOptions() traceRenderOptions
	TimeOptions() traceTimeOptions
}

// traceTimePolicy keeps TimeFormatter independent from unrelated render flags.
type traceTimePolicy interface {
	TimeOptions() traceTimeOptions
}

// traceFollowForkPolicy is the only exec-specific render decision.
type traceFollowForkPolicy interface {
	FollowForks() bool
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
	render             traceRenderOptions
}

var (
	_ traceFormatPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceEventOutputPolicy = (*cliTraceOutputPolicy)(nil)
	_ traceSummaryPolicy     = (*cliTraceOutputPolicy)(nil)
	_ traceExitPolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceRenderPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceTimePolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceFollowForkPolicy  = (*cliTraceOutputPolicy)(nil)
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
		render: traceRenderOptions{
			time: traceTimeOptions{
				printTimeMode:     opts.PrintTimeMode,
				printRelativeTime: opts.PrintRelativeTime,
			},
			followForks:       opts.FollowForks,
			alignCol:          opts.AlignCol,
			printSyscallTime:  opts.PrintSyscallTime,
			stackTrace:        opts.StackTrace,
			quietThreadExecve: opts.QuietThreadExecve,
		},
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

func (p *cliTraceOutputPolicy) RenderOptions() traceRenderOptions {
	if p == nil {
		return traceRenderOptions{}
	}
	return p.render
}

func (p *cliTraceOutputPolicy) TimeOptions() traceTimeOptions {
	if p == nil {
		return traceTimeOptions{}
	}
	return p.render.time
}

func (p *cliTraceOutputPolicy) FollowForks() bool {
	return p != nil && p.render.followForks
}
