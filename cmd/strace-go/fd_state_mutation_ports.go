package main

import "strace-go/pkg/meta"

// Mutation ports keep each event effect from receiving unrelated FD state writes.
type fdStateUpdatePort interface {
	ApplyFDState(fdStateUpdate)
}

type fdOffsetUpdatePort interface {
	ApplyFDOffsets(fdOffsetUpdate)
}

type fdCloseUpdatePort interface {
	CleanupClosedFD(fdCloseUpdate)
}

type fdLifecycleUpdatePort interface {
	InheritProcessState(parentPID int, childPID int)
	CleanupProcess(pid int)
	CloseOnExecProcess(pid int)
}

// fdOffsetUpdate is the immutable input for one exit-time offset transition.
type fdOffsetUpdate struct {
	view     syscallEventView
	meta     meta.Syscall
	statePID int
}

// fdCloseUpdate is the immutable input for one close-time descriptor cleanup.
type fdCloseUpdate struct {
	view     syscallEventView
	meta     meta.Syscall
	statePID int
}

var (
	_ fdStateUpdatePort     = (*FDStateStore)(nil)
	_ fdOffsetUpdatePort    = (*FDStateStore)(nil)
	_ fdCloseUpdatePort     = (*FDStateStore)(nil)
	_ fdLifecycleUpdatePort = (*FDStateStore)(nil)
)
