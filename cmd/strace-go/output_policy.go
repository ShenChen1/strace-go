package main

import "strace-go/pkg/cli"

// traceFormatPolicy exposes only the output format decision.
type traceFormatPolicy interface {
	IsJSON() bool
	DiscardEvents() bool
}

type traceReaderOnlyPolicy interface {
	ReaderOnly() bool
}

type traceHandlerOnlyPolicy interface {
	HandlerOnly() bool
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
	traceFormatPolicy
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

type traceLifecyclePolicy interface {
	traceFormatPolicy
	IsAttachTarget(pid int) bool
}

type traceReadyPolicy interface {
	DebugEvents() bool
	DebugPhases() bool
	AttachPIDs() []int
}

// cliTraceOutputPolicy is a session-scoped immutable snapshot of output policy.
type cliTraceOutputPolicy struct {
	json               bool
	discard            bool
	readerOnly         bool
	handlerOnly        bool
	debug              bool
	debugPhases        bool
	status             successfulFailedOptions
	statusFilterActive bool
	summaryOnly        bool
	summaryAndPrint    bool
	quietExit          bool
	render             traceRenderOptions
	attachPIDs         []int
}

var (
	_ traceFormatPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceEventOutputPolicy = (*cliTraceOutputPolicy)(nil)
	_ traceSummaryPolicy     = (*cliTraceOutputPolicy)(nil)
	_ traceExitPolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceRenderPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceTimePolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceFollowForkPolicy  = (*cliTraceOutputPolicy)(nil)
	_ traceScopePolicy       = (*cliTraceOutputPolicy)(nil)
	_ traceLifecyclePolicy   = (*cliTraceOutputPolicy)(nil)
	_ traceReadyPolicy       = (*cliTraceOutputPolicy)(nil)
	_ traceHandlerOnlyPolicy = (*cliTraceOutputPolicy)(nil)
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
		discard:            opts.EventFormat == cli.EventFormatNone || opts.EventFormat == cli.EventFormatReader || opts.EventFormat == cli.EventFormatHandler,
		readerOnly:         opts.EventFormat == cli.EventFormatReader,
		handlerOnly:        opts.EventFormat == cli.EventFormatHandler,
		debug:              opts.DebugEvents,
		debugPhases:        opts.DebugPhases,
		status:             successfulFailedOptions{successfulOnly: opts.SuccessfulOnly, failedOnly: opts.FailedOnly, traceStatus: traceStatus},
		statusFilterActive: opts.SuccessfulOnly || opts.FailedOnly || len(traceStatus) > 0,
		summaryOnly:        opts.SummaryOnly,
		summaryAndPrint:    opts.SummaryAndPrint,
		quietExit:          opts.QuietExit,
		attachPIDs:         append([]int(nil), opts.AttachPids...),
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

func (p *cliTraceOutputPolicy) DiscardEvents() bool {
	return p != nil && p.discard
}

// ReaderOnly identifies the diagnostic path that stops after event-v2 bounds validation.
func (p *cliTraceOutputPolicy) ReaderOnly() bool {
	return p != nil && p.readerOnly
}

// HandlerOnly identifies the diagnostic path that runs handlers without rendering output.
func (p *cliTraceOutputPolicy) HandlerOnly() bool {
	return p != nil && p.handlerOnly
}

func isTraceReaderOnlyPolicy(policy interface{}) bool {
	readerPolicy, ok := policy.(traceReaderOnlyPolicy)
	return ok && readerPolicy.ReaderOnly()
}

func isTraceHandlerOnlyPolicy(policy interface{}) bool {
	handlerPolicy, ok := policy.(traceHandlerOnlyPolicy)
	return ok && handlerPolicy.HandlerOnly()
}

func (p *cliTraceOutputPolicy) DebugEvents() bool {
	return p != nil && p.debug
}

func (p *cliTraceOutputPolicy) DebugPhases() bool {
	return p != nil && p.debugPhases
}

func (p *cliTraceOutputPolicy) ShouldEmit(ev syscallEventContext, unfinished bool) bool {
	if p == nil {
		return true
	}
	if p.discard {
		return false
	}
	if unfinished {
		return !p.statusFilterActive
	}
	if !p.statusFilterActive {
		return true
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

func (p *cliTraceOutputPolicy) IsAttachTarget(pid int) bool {
	if p == nil {
		return false
	}
	for _, attachedPID := range p.attachPIDs {
		if attachedPID == pid {
			return true
		}
	}
	return false
}

func (p *cliTraceOutputPolicy) AttachPIDs() []int {
	if p == nil {
		return nil
	}
	return append([]int(nil), p.attachPIDs...)
}
