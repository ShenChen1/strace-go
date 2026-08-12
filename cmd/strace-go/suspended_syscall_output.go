package main

import (
	"strace-go/pkg/handler"
)

type SuspendedSyscallOutput struct {
	state    suspendedSyscallState
	renderer unfinishedSyscallRenderer
}

type SuspendedSyscallOutputDeps struct {
	State    suspendedSyscallState
	Renderer unfinishedSyscallRenderer
}

func newSuspendedSyscallOutput(deps SuspendedSyscallOutputDeps) *SuspendedSyscallOutput {
	return &SuspendedSyscallOutput{
		state:    deps.State,
		renderer: deps.Renderer,
	}
}

// IMPACT: HandleEvent owns synthetic unfinished syscall enter events from the stable event context.
func (o *SuspendedSyscallOutput) HandleEvent(ev syscallEventContext, res handler.Result) bool {
	view := ev.eventView()
	switch view.probeRetEnter {
	case 3:
		if o.renderer != nil {
			o.renderer.PrintUnfinishedEvent(ev, res)
		}
		if o.state != nil {
			o.state.rememberSuspendedSyscall(int(view.tid), ev.syscallName())
		}
		return true
	case 2:
		return true
	default:
		return false
	}
}
