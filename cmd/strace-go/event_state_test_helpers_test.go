package main

func newTraceState() *TraceState {
	return &TraceState{trackForkIdentity: true, unfinishedEnabled: true}
}

func newTraceStateWithDeferredExit(enabled bool) *TraceState {
	return &TraceState{
		deferUnmatchedExits: enabled,
		trackForkIdentity:   true,
		unfinishedEnabled:   true,
	}
}
