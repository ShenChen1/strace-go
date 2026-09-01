package main

import "strace-go/pkg/cli"

// traceFormatPolicy exposes only the output format decision.
type traceFormatPolicy interface {
	IsJSON() bool
	DiscardEvents() bool
}

type traceDebugPhasesPolicy interface {
	DebugPhases() bool
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

// traceSignalOutputPolicy owns signal-set selection independently of syscalls.
type traceSignalOutputPolicy interface {
	ShouldEmitSignal(signo uint32) bool
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
	absoluteFormat    string
	absolutePrecision int
	relativePrecision int
}

type traceRenderOptions struct {
	time                 traceTimeOptions
	followForks          bool
	showPID              bool
	alwaysShowPID        bool
	alignCol             int
	printSyscallTime     bool
	syscallTimePrecision int
	printSyscallNumber   bool
	instructionPointer   bool
	printArgNames        bool
	stackTrace           bool
	stackTraceFrameLimit int
	quietThreadExecve    bool
	decodePIDsComm       bool
	decodePIDsPIDNS      bool
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

// traceFollowForkPolicy exposes the exec-specific render decisions.
type traceFollowForkPolicy interface {
	FollowForks() bool
	ArgNames() bool
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

type traceSeparateOutputPolicy interface {
	SeparateOutput() bool
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
	outputSeparate     bool
	render             traceRenderOptions
	attachPIDs         []int
	signals            map[int]bool
	signalConfigured   bool
	signalMatchesAll   bool
	signalSetIsNegated bool
}

var (
	_ traceFormatPolicy       = (*cliTraceOutputPolicy)(nil)
	_ traceEventOutputPolicy  = (*cliTraceOutputPolicy)(nil)
	_ traceSummaryPolicy      = (*cliTraceOutputPolicy)(nil)
	_ traceSignalOutputPolicy = (*cliTraceOutputPolicy)(nil)
	_ traceExitPolicy         = (*cliTraceOutputPolicy)(nil)
	_ traceRenderPolicy       = (*cliTraceOutputPolicy)(nil)
	_ traceTimePolicy         = (*cliTraceOutputPolicy)(nil)
	_ traceFollowForkPolicy   = (*cliTraceOutputPolicy)(nil)
	_ traceScopePolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceLifecyclePolicy    = (*cliTraceOutputPolicy)(nil)
	_ traceReadyPolicy        = (*cliTraceOutputPolicy)(nil)
	_ traceHandlerOnlyPolicy  = (*cliTraceOutputPolicy)(nil)
)

func newTraceOutputPolicy(opts *cli.Options) *cliTraceOutputPolicy {
	if opts == nil {
		return nil
	}
	traceStatus := make(map[string]bool, len(opts.TraceStatus))
	for name, enabled := range opts.TraceStatus {
		traceStatus[name] = enabled
	}
	traceSignals := make(map[int]bool, len(opts.TraceSignals))
	for signal, enabled := range opts.TraceSignals {
		traceSignals[signal] = enabled
	}
	alwaysShowPID := opts.AlwaysShowPID ||
		(opts.FollowForks && opts.OutFile != "" && !opts.OutputSeparate)
	return &cliTraceOutputPolicy{
		json:        opts.EventFormat == cli.EventFormatJSON,
		discard:     opts.EventFormat == cli.EventFormatNone || opts.EventFormat == cli.EventFormatReader || opts.EventFormat == cli.EventFormatHandler,
		readerOnly:  opts.EventFormat == cli.EventFormatReader || opts.EventFormat == cli.EventFormatNone,
		handlerOnly: opts.EventFormat == cli.EventFormatHandler,
		debug:       opts.DebugEvents,
		debugPhases: opts.DebugPhases,
		status: successfulFailedOptions{
			successfulOnly: opts.SuccessfulOnly,
			failedOnly:     opts.FailedOnly,
			traceStatus:    traceStatus,
			statusSet:      opts.StatusConfigured,
		},
		statusFilterActive: opts.SuccessfulOnly || opts.FailedOnly || opts.StatusConfigured || len(traceStatus) > 0,
		summaryOnly:        opts.SummaryOnly,
		summaryAndPrint:    opts.SummaryAndPrint,
		quietExit:          opts.QuietExit,
		outputSeparate:     opts.OutputSeparate,
		attachPIDs:         append([]int(nil), opts.AttachPids...),
		signals:            traceSignals,
		signalConfigured:   opts.SignalConfigured,
		signalMatchesAll:   opts.SignalMatchesAll,
		signalSetIsNegated: opts.SignalSetIsNegated,
		render: traceRenderOptions{
			time:                 normalizedTimeOptions(opts),
			followForks:          opts.FollowForks,
			showPID:              (opts.FollowForks || opts.AlwaysShowPID) && !opts.OutputSeparate,
			alwaysShowPID:        alwaysShowPID,
			alignCol:             opts.AlignCol,
			printSyscallTime:     opts.PrintSyscallTime,
			syscallTimePrecision: timestampPrecisionWidth(opts.SyscallTimePrecision, 6),
			printSyscallNumber:   opts.PrintSyscallNumber,
			instructionPointer:   opts.InstructionPointer,
			printArgNames:        opts.PrintArgNames,
			stackTrace:           opts.StackTrace,
			stackTraceFrameLimit: normalizedStackTraceFrameLimit(opts.StackFrameLimit),
			quietThreadExecve:    opts.QuietThreadExecve,
			decodePIDsComm:       opts.DecodePIDsComm,
			decodePIDsPIDNS:      opts.DecodePIDsPIDNS,
		},
	}
}

func normalizedStackTraceFrameLimit(limit int) int {
	if limit <= 0 {
		return cli.DefaultStackTraceFrameLimit
	}
	return limit
}

func normalizedTimeOptions(opts *cli.Options) traceTimeOptions {
	options := traceTimeOptions{
		printTimeMode:     opts.PrintTimeMode,
		printRelativeTime: opts.PrintRelativeTime,
		relativePrecision: timestampPrecisionWidth(opts.RelativeTimePrecision, 6),
	}
	if opts.AbsoluteTimeFormat != "" {
		if opts.AbsoluteTimeFormat != "none" {
			options.absoluteFormat = opts.AbsoluteTimeFormat
			options.absolutePrecision = timestampPrecisionWidth(opts.AbsoluteTimePrecision, 0)
		}
		return options
	}
	switch opts.PrintTimeMode {
	case 1:
		options.absoluteFormat = "time"
	case 2:
		options.absoluteFormat = "time"
		options.absolutePrecision = 6
	case 3:
		options.absoluteFormat = "unix"
		options.absolutePrecision = 6
	}
	return options
}

func timestampPrecisionWidth(precision string, defaultWidth int) int {
	switch precision {
	case "s":
		return 0
	case "ms":
		return 3
	case "us":
		return 6
	case "ns":
		return 9
	default:
		return defaultWidth
	}
}

func (p *cliTraceOutputPolicy) IsJSON() bool {
	return p != nil && p.json
}

func (p *cliTraceOutputPolicy) DiscardEvents() bool {
	return p != nil && p.discard
}

// ReaderOnly identifies diagnostic paths that stop after event-v2 bounds validation.
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

func isTraceDebugPhasesPolicy(policy interface{}) bool {
	debugPolicy, ok := policy.(traceDebugPhasesPolicy)
	return ok && debugPolicy.DebugPhases()
}

func (p *cliTraceOutputPolicy) ShouldEmit(ev syscallEventContext, unfinished bool) bool {
	if p == nil {
		return true
	}
	if p.discard {
		return false
	}
	if unfinished {
		return !p.statusFilterActive ||
			(p.status.hasStatusSet() && p.status.traceStatus["unfinished"])
	}
	if !p.statusFilterActive {
		return true
	}
	return ev.shouldEmitStatus(p.status)
}

func (p *cliTraceOutputPolicy) ShouldEmitSignal(signo uint32) bool {
	if p == nil {
		return true
	}
	if p.discard || p.json || p.summaryOnly {
		return false
	}
	if !p.signalConfigured || p.signalMatchesAll {
		return true
	}
	matched := p.signals[int(signo)]
	if p.signalSetIsNegated {
		return !matched
	}
	return matched
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

func (p *cliTraceOutputPolicy) SeparateOutput() bool {
	return p != nil && p.outputSeparate
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

func (p *cliTraceOutputPolicy) ArgNames() bool {
	return p != nil && p.render.printArgNames
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
