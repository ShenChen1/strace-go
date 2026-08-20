package main

import "strace-go/pkg/meta"

func newTraceState() *TraceState {
	return &TraceState{
		trackForkIdentity: true,
		unfinishedEnabled: true,
		lifecycleIDs:      newSyscallLifecycleIDs(meta.SyscallTable),
	}
}

func newTraceStateWithDeferredExit(enabled bool) *TraceState {
	return &TraceState{
		deferUnmatchedExits: enabled,
		trackForkIdentity:   true,
		unfinishedEnabled:   true,
		lifecycleIDs:        newSyscallLifecycleIDs(meta.SyscallTable),
	}
}
