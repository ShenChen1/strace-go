package main

import "strace-go/pkg/meta"

func newTraceState() *TraceState {
	return &TraceState{
		unfinished:   traceUnfinishedState{enabled: true},
		lifecycle:    traceTaskLifecycleState{trackForkIdentity: true},
		lifecycleIDs: newSyscallLifecycleIDs(meta.SyscallTable),
	}
}

func newTraceStateWithDeferredExit(enabled bool) *TraceState {
	return &TraceState{
		deferUnmatchedExits: enabled,
		unfinished:          traceUnfinishedState{enabled: true},
		lifecycle:           traceTaskLifecycleState{trackForkIdentity: true},
		lifecycleIDs:        newSyscallLifecycleIDs(meta.SyscallTable),
	}
}
