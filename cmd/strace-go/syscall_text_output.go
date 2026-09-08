package main

import "strace-go/pkg/handler"

type suspendedSyscallOutputPort interface {
	HandleEvent(syscallEventContext, handler.Result) bool
}

type execSyscallOutputPort interface {
	HandleEvent(syscallEventContext, handler.Result) bool
}

type SyscallTextOutput struct {
	format    traceFormatPolicy
	policy    traceEventOutputPolicy
	suspended suspendedSyscallOutputPort
	exec      execSyscallOutputPort
	renderer  syscallTextRenderer
}

type SyscallTextOutputDeps struct {
	Format    traceFormatPolicy
	Policy    traceEventOutputPolicy
	Suspended suspendedSyscallOutputPort
	Exec      execSyscallOutputPort
	Renderer  syscallTextRenderer
}

func newSyscallTextOutput(deps SyscallTextOutputDeps) *SyscallTextOutput {
	return &SyscallTextOutput{
		format:    deps.Format,
		policy:    deps.Policy,
		suspended: deps.Suspended,
		exec:      deps.Exec,
		renderer:  deps.Renderer,
	}
}

func (s *traceSession) syscallTextOutput() *SyscallTextOutput {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.syscallText
}

// IMPACT: HandleEvent owns text-mode syscall output from the stable syscall event context.
func (o *SyscallTextOutput) HandleEvent(ev syscallEventContext, res handler.Result) {
	if o.suspended != nil && o.suspended.HandleEvent(ev, res) {
		return
	}
	if !o.shouldEmitEvent(ev) {
		return
	}
	if o.exec != nil && o.exec.HandleEvent(ev, res) {
		return
	}
	if o.renderer != nil {
		o.renderer.PrintSyscallEvent(ev, res)
	}
}

func (o *SyscallTextOutput) HandleUnfinished(ev syscallEventContext, res handler.Result) bool {
	if !o.canHandleUnfinished(ev) {
		return false
	}
	o.renderer.PrintUnfinishedEvent(ev, res)
	return true
}

func (o *SyscallTextOutput) canHandleUnfinished(ev syscallEventContext) bool {
	if o == nil || o.renderer == nil || !o.textMode() || !ev.shouldOutput() {
		return false
	}
	if o.policy == nil {
		return true
	}
	return o.policy.ShouldEmit(ev, true)
}

func (o *SyscallTextOutput) textMode() bool {
	return o.format == nil || (!o.format.IsJSON() && !o.format.DiscardEvents() &&
		(o.policy == nil || !o.policy.DebugEvents()))
}

func (o *SyscallTextOutput) shouldEmitEvent(ev syscallEventContext) bool {
	if o.policy == nil {
		return true
	}
	return o.policy.ShouldEmit(ev, false)
}
