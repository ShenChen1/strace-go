package main

// traceStateOwner exists only at the session composition boundary.
// Runtime consumers receive the narrow state capability they require.
type traceStateOwner interface {
	traceEventState
	traceUnfinishedStateConfigurator
	tracePendingStateReader
	textRendererState
	execSyscallState
	suspendedSyscallState
	traceAttachStateReader
}

var _ traceStateOwner = (*TraceState)(nil)
