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
	components := s.componentsOrBuild()
	if components == nil {
		return nil
	}
	return components.syscallText
}

// IMPACT: HandleEvent owns text-mode syscall output from the stable syscall event context.
func (o *SyscallTextOutput) HandleEvent(ev syscallEventContext, res handler.Result) {
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
	if o.opts == nil {
		return true
	}
	return !o.opts.SuccessfulOnly && !o.opts.FailedOnly && len(o.opts.TraceStatus) == 0
}

func (o *SyscallTextOutput) textMode() bool {
	return o.opts == nil || (o.opts.EventFormat != cli.EventFormatJSON && !o.opts.DebugEvents)
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
