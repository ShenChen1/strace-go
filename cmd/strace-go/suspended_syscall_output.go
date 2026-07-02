package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type SuspendedSyscallOutput struct {
	state    *TraceState
	renderer *TextRenderer
}

type SuspendedSyscallOutputDeps struct {
	State    *TraceState
	Renderer *TextRenderer
}

func newSuspendedSyscallOutput(deps SuspendedSyscallOutputDeps) *SuspendedSyscallOutput {
	return &SuspendedSyscallOutput{
		state:    deps.State,
		renderer: deps.Renderer,
	}
}

func (s *traceSession) suspendedSyscallOutput() *SuspendedSyscallOutput {
	return newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
		State:    s.traceState(),
		Renderer: s.textRenderer(),
	})
}

// IMPACT: Handle owns synthetic unfinished syscall enter events from BPF probe state.
func (o *SuspendedSyscallOutput) Handle(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result) bool {
	switch eventRaw.ProbeRetEnter {
	case 3:
		if o.renderer != nil {
			o.renderer.PrintUnfinished(eventRaw, scMeta, res)
		}
		if o.state != nil {
			o.state.rememberSuspendedSyscall(int(eventRaw.Tid), scMeta.Name)
		}
		return true
	case 2:
		return true
	default:
		return false
	}
}
