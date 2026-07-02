package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
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

// IMPACT: Handle owns the text-mode syscall output chain after handler decoding.
func (o *SyscallTextOutput) Handle(ctx *handler.Context, eventRaw *bpfEvent, res handler.Result) {
	scMeta := ctx.ScMeta
	if !o.shouldEmit(eventRaw, scMeta) {
		return
	}
	if o.suspended != nil && o.suspended.Handle(eventRaw, scMeta, res) {
		return
	}
	if o.exec != nil && o.exec.Handle(eventRaw, scMeta, res) {
		return
	}
	if o.renderer != nil {
		o.renderer.PrintSyscall(eventRaw, scMeta, res, ctx)
	}
}

func (o *SyscallTextOutput) shouldEmit(eventRaw *bpfEvent, scMeta meta.Syscall) bool {
	if o.opts == nil {
		return true
	}
	status := successfulFailedOptions{
		successfulOnly: o.opts.SuccessfulOnly,
		failedOnly:     o.opts.FailedOnly,
		traceStatus:    o.opts.TraceStatus,
	}
	return shouldEmitStatus(eventRaw, scMeta, status)
}
