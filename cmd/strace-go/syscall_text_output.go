package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type SyscallTextOutput struct {
	opts      *cli.Options
	suspended *SuspendedSyscallOutput
	exec      *ExecSyscallOutput
	renderer  *TextRenderer
}

type SyscallTextOutputDeps struct {
	Opts      *cli.Options
	Suspended *SuspendedSyscallOutput
	Exec      *ExecSyscallOutput
	Renderer  *TextRenderer
}

func newSyscallTextOutput(deps SyscallTextOutputDeps) *SyscallTextOutput {
	return &SyscallTextOutput{
		opts:      deps.Opts,
		suspended: deps.Suspended,
		exec:      deps.Exec,
		renderer:  deps.Renderer,
	}
}

func (s *traceSession) syscallTextOutput() *SyscallTextOutput {
	if s.syscallTextCache == nil {
		renderer := s.textRenderer()
		state := s.traceState()
		exitStatus := s.exitStatusCoordinator()
		s.syscallTextCache = newSyscallTextOutput(SyscallTextOutputDeps{
			Opts: s.opts,
			Suspended: newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
				State:    state,
				Renderer: renderer,
			}),
			Exec: newExecSyscallOutput(ExecSyscallOutputDeps{
				Opts:              s.opts,
				State:             state,
				Renderer:          renderer,
				DiscardExitStatus: exitStatus.Discard,
			}),
			Renderer: renderer,
		})
	}
	return s.syscallTextCache
}

// IMPACT: HandleEvent owns text-mode syscall output from the stable syscall event context.
func (o *SyscallTextOutput) HandleEvent(ev syscallEventContext, res handler.Result) {
	scMeta := ev.meta
	if scMeta.Name == "" && ev.handlerContext != nil {
		scMeta = ev.handlerContext.ScMeta
		ev.meta = scMeta
	}
	if !o.shouldEmitEvent(ev) {
		return
	}
	if o.suspended != nil && o.suspended.HandleEvent(ev, res) {
		return
	}
	if o.exec != nil && o.exec.HandleEvent(ev, res) {
		return
	}
	if o.renderer != nil {
		o.renderer.PrintSyscallEvent(ev, res)
	}
}

func (o *SyscallTextOutput) shouldEmitEvent(ev syscallEventContext) bool {
	if o.opts == nil {
		return true
	}
	status := successfulFailedOptions{
		successfulOnly: o.opts.SuccessfulOnly,
		failedOnly:     o.opts.FailedOnly,
		traceStatus:    o.opts.TraceStatus,
	}
	return ev.shouldEmitStatus(status)
}
