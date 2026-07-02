package main

import "strace-go/pkg/cli"

type TraceScope struct {
	targetPID  int
	attachPIDs []int
	followFork bool
}

func newTraceScope(targetPID int, opts *cli.Options) TraceScope {
	scope := TraceScope{targetPID: targetPID}
	if opts != nil {
		scope.attachPIDs = append([]int(nil), opts.AttachPids...)
		scope.followFork = opts.FollowForks
	}
	return scope
}

func (s *traceSession) traceScope() TraceScope {
	return newTraceScope(s.targetPid, s.opts)
}

func (scope TraceScope) Allows(eventRaw *bpfEvent) bool {
	if eventRaw == nil {
		return false
	}
	if scope.directlyMatches(int(eventRaw.Pid)) {
		return true
	}
	return scope.followFork
}

func (scope TraceScope) directlyMatches(pid int) bool {
	if len(scope.attachPIDs) > 0 {
		for _, attachedPID := range scope.attachPIDs {
			if pid == attachedPID {
				return true
			}
		}
		return false
	}
	return pid == scope.targetPID
}
