package main

type traceEventState interface {
	handleEnvelope(traceEventEnvelope) TraceStateUpdate
	releaseTraceStateUpdate(TraceStateUpdate)
	markUnfinishedPrinted(uint32)
	requeueUnfinished(uint32)
}

type traceEventUpdateDispatcher interface {
	Dispatch(traceEventEnvelope, TraceStateUpdate)
}

// traceUnfinishedStateConfigurator is used only while the session graph is
// composed, before the event router receives its runtime state port.
type traceUnfinishedStateConfigurator interface {
	setUnfinishedEnabled(bool)
}

type tracePendingStateReader interface {
	PendingStaleCount() int
}

type textRendererState interface {
	consumeSuspendedSyscall(int) bool
}

type execSyscallState interface {
	rememberPendingExecArgs(int, string)
	takePendingExecArgs(int) (string, bool)
	pendingExecArgsFor(int) (string, bool)
	deletePendingExecArgs(int)
	deleteSuspendedSyscall(int)
}

type suspendedSyscallState interface {
	rememberSuspendedSyscall(int, string)
}

var (
	_ traceEventState                  = (*TraceState)(nil)
	_ traceEventUpdateDispatcher       = (*TraceEventDispatcher)(nil)
	_ traceUnfinishedStateConfigurator = (*TraceState)(nil)
	_ tracePendingStateReader          = (*TraceState)(nil)
	_ textRendererState                = (*TraceState)(nil)
	_ execSyscallState                 = (*TraceState)(nil)
	_ suspendedSyscallState            = (*TraceState)(nil)
)
