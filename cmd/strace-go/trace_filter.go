package main

import (
	"regexp"

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
	traceSyscalls       map[string]bool
	traceSyscallRegexps []*regexp.Regexp
	traceSetIsNegated   bool
	traceFDs            map[int32]bool
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
	return !filter.traceSetIsNegated &&
		len(filter.traceSyscalls) == 0 &&
		len(filter.traceSyscallRegexps) == 0 &&
		len(filter.traceFDs) == 0 &&
		!filter.traceFDsNegated &&
		len(filter.traceReadFDs) == 0 &&
		!filter.traceReadNegated &&
		len(filter.traceWriteFDs) == 0 &&
		!filter.traceWriteNegated &&
		(filter.pathFilter == nil || filter.pathFilter.Empty())
}

func (filter cliTraceFilter) MatchSyscall(name string) bool {
	matched := len(filter.traceSyscalls) == 0 && len(filter.traceSyscallRegexps) == 0
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
	if len(filter.traceFDs) == 0 {
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
		if filter.traceFDs[fd] {
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
	return len(filter.traceFDs) > 0
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
