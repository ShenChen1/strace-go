package main

import (
	"fmt"
	"io"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type ExitSyscallOutput struct {
	opts              *cli.Options
	renderer          *TextRenderer
	out               io.Writer
	shouldQueueStatus func(int) bool
	queueStatus       func(int, string)
	writeJSON         func(syscallEventContext, handler.Result)
}

type ExitSyscallOutputDeps struct {
	Opts              *cli.Options
	Renderer          *TextRenderer
	Out               io.Writer
	ShouldQueueStatus func(int) bool
	QueueStatus       func(int, string)
	WriteJSON         func(syscallEventContext, handler.Result)
}

func newExitSyscallOutput(deps ExitSyscallOutputDeps) *ExitSyscallOutput {
	return &ExitSyscallOutput{
		opts:              deps.Opts,
		renderer:          deps.Renderer,
		out:               deps.Out,
		shouldQueueStatus: deps.ShouldQueueStatus,
		queueStatus:       deps.QueueStatus,
		writeJSON:         deps.WriteJSON,
	}
}

func (s *traceSession) exitSyscallOutput() *ExitSyscallOutput {
	if s.exitSyscallCache == nil {
		exitStatus := s.exitStatusCoordinator()
		s.exitSyscallCache = newExitSyscallOutput(ExitSyscallOutputDeps{
			Opts:              s.opts,
			Renderer:          s.textRenderer(),
			Out:               s.outWriter,
			ShouldQueueStatus: exitStatus.ShouldQueue,
			QueueStatus:       exitStatus.Queue,
			WriteJSON:         s.writeJSONDecodedEvent,
		})
	}
	return s.exitSyscallCache
}

// IMPACT: Handle owns exit/exit_group text, JSON, and exit-status queue output.
func (o *ExitSyscallOutput) Handle(ev syscallEventContext) bool {
	if !ev.isExitSyscallEvent() {
		return false
	}
	if o.opts != nil && o.opts.SummaryOnly {
		return true
	}

	if ev.shouldOutput() {
		res := ev.handleWith(defaultHandleSyscall)
		if o.opts != nil && o.opts.EventFormat == cli.EventFormatJSON {
			if o.writeJSON != nil {
				o.writeJSON(ev, res)
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
	if o.opts != nil && o.opts.QuietExit {
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
		fmt.Fprint(o.out, exitLine)
	}
}

func (ev syscallEventContext) isExitSyscallEvent() bool {
	name := ev.syscallName()
	return ev.eventView().isExit() && (name == "exit" || name == "exit_group")
}
