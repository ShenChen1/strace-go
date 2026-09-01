package main

import (
	"regexp"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

// traceFilterOptions is the event-side view of CLI filtering policy.
type traceFilterOptions interface {
	DebugEvents() bool
	IsUnfiltered() bool
	MatchSyscall(name string) bool
	MatchFDs(fds []int32) bool
	HasFDFilter() bool
	TraceReadFD(fd int32) bool
	TraceWriteFD(fd int32) bool
	PathFilter() event.PathFilter
}

type cliTraceFilter struct {
	debug               bool
	unfiltered          bool
	traceSyscalls       map[string]bool
	traceSyscallRegexps []*regexp.Regexp
	traceConfigured     bool
	traceMatchesAll     bool
	traceSetIsNegated   bool
	traceFDs            map[int32]bool
	traceFDsConfigured  bool
	traceFDsNegated     bool
	traceReadFDs        map[int32]bool
	traceReadNegated    bool
	traceWriteFDs       map[int32]bool
	traceWriteNegated   bool
	pathFilter          event.PathFilter
}

var _ traceFilterOptions = (*cliTraceFilter)(nil)

func (filter cliTraceFilter) DebugEvents() bool {
	return filter.debug
}

func (filter cliTraceFilter) IsUnfiltered() bool {
	return filter.unfiltered
}

func (filter cliTraceFilter) MatchSyscall(name string) bool {
	if isUnknownSyscallName(name) {
		return true
	}
	if !filter.traceConfigured || filter.traceMatchesAll {
		return true
	}
	matched := false
	if !matched {
		matched = filter.traceSyscalls[name]
		if !matched {
			for _, expression := range filter.traceSyscallRegexps {
				if expression.MatchString(name) {
					matched = true
					break
				}
			}
		}
	}
	if filter.traceSetIsNegated {
		return !matched
	}
	return matched
}

func (filter cliTraceFilter) MatchFDs(fds []int32) bool {
	if !filter.traceFDsConfigured {
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
		if filter.traceFDs[cli.TraceAllFDs] || filter.traceFDs[fd] {
			matchesSet = true
		} else {
			matchesNegatedSet = true
		}
	}
	if filter.traceFDsNegated {
		return hasValidFD && matchesNegatedSet
	}
	return matchesSet
}

func (filter cliTraceFilter) HasFDFilter() bool {
	return filter.traceFDsConfigured
}

func (filter cliTraceFilter) TraceReadFD(fd int32) bool {
	return matchTraceFD(fd, filter.traceReadFDs, filter.traceReadNegated)
}

func (filter cliTraceFilter) TraceWriteFD(fd int32) bool {
	return matchTraceFD(fd, filter.traceWriteFDs, filter.traceWriteNegated)
}

func (filter cliTraceFilter) PathFilter() event.PathFilter {
	return filter.pathFilter
}
