package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

// traceFilterOptions is the event-side view of CLI filtering policy.
type traceFilterOptions interface {
	DebugEvents() bool
	MatchSyscall(name string) bool
	MatchFDs(fds []int32) bool
	HasFDFilter() bool
	TraceReadFD(fd int32) bool
	TraceWriteFD(fd int32) bool
	PathFilter() event.PathFilter
}

type cliTraceFilter struct {
	opts       *cli.Options
	pathFilter event.PathFilter
}

var _ traceFilterOptions = cliTraceFilter{}

func newTraceFilterOptions(opts *cli.Options) traceFilterOptions {
	if opts == nil {
		return nil
	}
	paths := event.TracePathSet(opts.TracePaths)
	var pathFilter event.PathFilter
	if !paths.Empty() {
		pathFilter = paths
	}
	return cliTraceFilter{opts: opts, pathFilter: pathFilter}
}

func (filter cliTraceFilter) DebugEvents() bool {
	return filter.opts != nil && filter.opts.DebugEvents
}

func (filter cliTraceFilter) MatchSyscall(name string) bool {
	if filter.opts == nil {
		return true
	}
	matched := len(filter.opts.TraceSyscalls) == 0 && len(filter.opts.TraceSyscallRegexps) == 0
	if !matched {
		matched = filter.opts.TraceSyscalls[name]
		if !matched {
			for _, expression := range filter.opts.TraceSyscallRegexps {
				if expression.MatchString(name) {
					matched = true
					break
				}
			}
		}
	}
	if filter.opts.TraceSetIsNegated {
		return !matched
	}
	return matched
}

func (filter cliTraceFilter) MatchFDs(fds []int32) bool {
	if filter.opts == nil || len(filter.opts.TraceFDs) == 0 {
		return false
	}
	hasValidFD := false
	matchesSet := false
	matchesNegatedSet := false
	for _, fd := range fds {
		if fd < 0 {
			continue
		}
		hasValidFD = true
		if filter.opts.TraceFDs[fd] {
			matchesSet = true
		} else {
			matchesNegatedSet = true
		}
	}
	if filter.opts.TraceFDsNegated {
		return hasValidFD && matchesNegatedSet
	}
	return matchesSet
}

func (filter cliTraceFilter) HasFDFilter() bool {
	return filter.opts != nil && len(filter.opts.TraceFDs) > 0
}

func (filter cliTraceFilter) TraceReadFD(fd int32) bool {
	return filter.opts != nil && filter.opts.TraceReadFD(fd)
}

func (filter cliTraceFilter) TraceWriteFD(fd int32) bool {
	return filter.opts != nil && filter.opts.TraceWriteFD(fd)
}

func (filter cliTraceFilter) PathFilter() event.PathFilter {
	return filter.pathFilter
}
