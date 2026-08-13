package main

import (
	"regexp"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

// cliTraceEventPolicy is the one construction-time snapshot used by syscall
// event contexts. Its ports stay separate so handlers and filters cannot see
// each other's policy fields.
type cliTraceEventPolicy struct {
	handlerOptions      handler.OptionsPort
	filter              traceFilterOptions
	deferUnmatchedExits bool
	trackForkIdentity   bool
}

type traceStatePolicy interface {
	ShouldDeferUnmatchedExits() bool
	TrackForkIdentity() bool
}

var _ traceStatePolicy = (*cliTraceEventPolicy)(nil)

func newTraceEventPolicy(opts *cli.Options) *cliTraceEventPolicy {
	if opts == nil {
		return nil
	}
	return &cliTraceEventPolicy{
		handlerOptions:      newTraceHandlerOptions(opts),
		filter:              newTraceFilterOptions(opts),
		deferUnmatchedExits: shouldEmitGenericEnter(opts),
		trackForkIdentity:   opts.FollowForks,
	}
}

func (p *cliTraceEventPolicy) ShouldDeferUnmatchedExits() bool {
	return p != nil && p.deferUnmatchedExits
}

func (p *cliTraceEventPolicy) TrackForkIdentity() bool {
	return p == nil || p.trackForkIdentity
}

func (p *cliTraceEventPolicy) HandlerOptions() handler.OptionsPort {
	if p == nil {
		return nil
	}
	return p.handlerOptions
}

func (p *cliTraceEventPolicy) FilterOptions() traceFilterOptions {
	if p == nil {
		return nil
	}
	return p.filter
}

type cliTraceHandlerOptions struct {
	stringLimit       int
	hexEscapeMode     int
	verbose           bool
	verboseDisabled   map[string]bool
	showPaths         bool
	showPathsMode     int
	traceReadFDs      map[int32]bool
	traceReadNegated  bool
	traceWriteFDs     map[int32]bool
	traceWriteNegated bool
}

func newTraceHandlerOptions(opts *cli.Options) handler.OptionsPort {
	if opts == nil {
		return nil
	}
	return &cliTraceHandlerOptions{
		stringLimit:       opts.StringLimit,
		hexEscapeMode:     opts.HexEscapeMode,
		verbose:           opts.Verbose,
		verboseDisabled:   copyStringBoolMap(opts.VerboseDisabled),
		showPaths:         opts.ShowPaths,
		showPathsMode:     opts.ShowPathsMode,
		traceReadFDs:      copyInt32BoolMap(opts.TraceReadFDs),
		traceReadNegated:  opts.TraceReadFDsNegated,
		traceWriteFDs:     copyInt32BoolMap(opts.TraceWriteFDs),
		traceWriteNegated: opts.TraceWriteFDsNegated,
	}
}

func (o cliTraceHandlerOptions) StringLimitValue() int { return o.stringLimit }

func (o cliTraceHandlerOptions) HexEscapeModeValue() int { return o.hexEscapeMode }

func (o cliTraceHandlerOptions) VerboseValue() bool { return o.verbose }

func (o cliTraceHandlerOptions) VerboseDisabledFor(name string) bool {
	return o.verboseDisabled[name]
}

func (o cliTraceHandlerOptions) ShowPathsValue() bool { return o.showPaths }

func (o cliTraceHandlerOptions) ShowPathsModeValue() int { return o.showPathsMode }

func (o cliTraceHandlerOptions) TraceReadFD(fd int32) bool {
	return matchTraceFD(fd, o.traceReadFDs, o.traceReadNegated)
}

func (o cliTraceHandlerOptions) TraceWriteFD(fd int32) bool {
	return matchTraceFD(fd, o.traceWriteFDs, o.traceWriteNegated)
}

func matchTraceFD(fd int32, values map[int32]bool, negated bool) bool {
	if negated {
		return !values[cli.TraceAllFDs] && !values[fd]
	}
	return values[cli.TraceAllFDs] || values[fd]
}

func newTraceFilterOptions(opts *cli.Options) traceFilterOptions {
	if opts == nil {
		return nil
	}
	paths := copyStringBoolMap(opts.TracePaths)
	var pathFilter event.PathFilter
	if candidate := event.TracePathSet(paths); !candidate.Empty() {
		pathFilter = candidate
	}
	return &cliTraceFilter{
		debug:               opts.DebugEvents,
		traceSyscalls:       copyStringBoolMap(opts.TraceSyscalls),
		traceSyscallRegexps: append([]*regexp.Regexp(nil), opts.TraceSyscallRegexps...),
		traceSetIsNegated:   opts.TraceSetIsNegated,
		traceFDs:            copyInt32BoolMap(opts.TraceFDs),
		traceFDsNegated:     opts.TraceFDsNegated,
		traceReadFDs:        copyInt32BoolMap(opts.TraceReadFDs),
		traceReadNegated:    opts.TraceReadFDsNegated,
		traceWriteFDs:       copyInt32BoolMap(opts.TraceWriteFDs),
		traceWriteNegated:   opts.TraceWriteFDsNegated,
		pathFilter:          pathFilter,
	}
}

func copyStringBoolMap(source map[string]bool) map[string]bool {
	if len(source) == 0 {
		return nil
	}
	copied := make(map[string]bool, len(source))
	for key, value := range source {
		copied[key] = value
	}
	return copied
}

func copyInt32BoolMap(source map[int32]bool) map[int32]bool {
	if len(source) == 0 {
		return nil
	}
	copied := make(map[int32]bool, len(source))
	for key, value := range source {
		copied[key] = value
	}
	return copied
}
