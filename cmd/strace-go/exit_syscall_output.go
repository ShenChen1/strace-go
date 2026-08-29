package main

import (
	"fmt"
	"io"

	"strace-go/pkg/handler"
)

type ExitSyscallOutput struct {
	policy            traceExitPolicy
	renderer          exitSyscallRenderer
	out               io.Writer
	handleSyscall     func(string, *handler.Context) handler.Result
	shouldQueueStatus func(int) bool
	queueStatus       func(int, string)
	jsonWriter        jsonEventWriter
}

type ExitSyscallOutputDeps struct {
	Policy            traceExitPolicy
	Renderer          exitSyscallRenderer
	Out               io.Writer
	HandleSyscall     func(string, *handler.Context) handler.Result
	ShouldQueueStatus func(int) bool
	QueueStatus       func(int, string)
	JSONWriter        jsonEventWriter
}

func newExitSyscallOutput(deps ExitSyscallOutputDeps) *ExitSyscallOutput {
	return &ExitSyscallOutput{
		policy:            deps.Policy,
		renderer:          deps.Renderer,
		out:               deps.Out,
		handleSyscall:     deps.HandleSyscall,
		shouldQueueStatus: deps.ShouldQueueStatus,
		queueStatus:       deps.QueueStatus,
		jsonWriter:        deps.JSONWriter,
	}
}

func (s *traceSession) exitSyscallOutput() *ExitSyscallOutput {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.exitSyscall
}

// IMPACT: Handle owns exit/exit_group text, JSON, and exit-status queue output.
func (o *ExitSyscallOutput) Handle(ev syscallEventContext) bool {
	if !ev.isExitSyscallEvent() {
		return false
	}
	if o.policy != nil && o.policy.DiscardEvents() {
		return true
	}
	if o.policy != nil && o.policy.SummaryOnly() {
		return true
	}

	if ev.shouldOutput() {
		handleSyscall := o.handleSyscall
		if handleSyscall == nil {
			handleSyscall = defaultHandleSyscall
		}
		res := ev.handleWith(handleSyscall)
		if o.policy != nil && o.policy.IsJSON() {
			if o.jsonWriter != nil {
				o.jsonWriter.WriteDecoded(ev, res)
			}
			return true
		}
		if o.renderer != nil {
			o.renderer.PrintExitSyscallEvent(ev, res)
		}
	}
	o.printExitStatus(ev)
	return true
}

func (o *ExitSyscallOutput) printExitStatus(ev syscallEventContext) {
	if o.policy != nil && (o.policy.QuietExit() || o.policy.DiscardEvents()) {
		return
	}
	if o.renderer == nil {
		return
	}
	view := ev.eventView()
	exitLine := o.renderer.ExitStatusLineFromView(view)
	if o.shouldQueueStatus != nil && o.shouldQueueStatus(int(view.pid)) {
		if o.queueStatus != nil {
			o.queueStatus(int(view.tid), exitLine)
		}
		return
	}
	if o.out != nil {
		selectTraceOutputPID(o.out, int(view.tid))
		fmt.Fprint(o.out, exitLine)
	}
}

func (ev syscallEventContext) isExitSyscallEvent() bool {
	return ev.eventView().isExit() && ev.eventTraits()&syscallEventTraitExit != 0
}
