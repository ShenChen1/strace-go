package main

type traceEventState interface {
	handleEnvelope(traceEventEnvelope) TraceStateUpdate
	markUnfinishedPrinted(uint32)
	requeueUnfinished(uint32)
	setUnfinishedEnabled(bool)
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
	_ traceEventState       = (*TraceState)(nil)
	_ textRendererState     = (*TraceState)(nil)
	_ execSyscallState      = (*TraceState)(nil)
	_ suspendedSyscallState = (*TraceState)(nil)
)
