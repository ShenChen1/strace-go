package main

type lifecycleEventSink interface {
	Handle(lifecycleEventView, *TaskState)
	InheritProcessState(parentPID int, childPID int)
}

type syscallEnterSink interface {
	HandleEnter(syscallEventContext)
}

type syscallExitSink interface {
	Handle(syscallEventContext)
	HandleUnfinished(syscallEventContext) bool
	HasTextOutput() bool
}

var (
	_ lifecycleEventSink = (*LifecycleEventHandler)(nil)
	_ signalEventSink    = (*SignalEventOutput)(nil)
	_ syscallEnterSink   = (*SyscallJSONOutput)(nil)
	_ syscallExitSink    = (*SyscallExitPipeline)(nil)
)
