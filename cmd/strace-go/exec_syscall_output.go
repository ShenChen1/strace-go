package main

import (
	"fmt"
	"strings"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type ExecSyscallOutput struct {
	opts              *cli.Options
	state             *TraceState
	renderer          *TextRenderer
	discardExitStatus func(int)
}

type ExecSyscallOutputDeps struct {
	Opts              *cli.Options
	State             *TraceState
	Renderer          *TextRenderer
	DiscardExitStatus func(int)
}

func newExecSyscallOutput(deps ExecSyscallOutputDeps) *ExecSyscallOutput {
	return &ExecSyscallOutput{
		opts:              deps.Opts,
		state:             deps.State,
		renderer:          deps.Renderer,
		discardExitStatus: deps.DiscardExitStatus,
	}
}

func (s *traceSession) execSyscallOutput() *ExecSyscallOutput {
	exitStatus := s.exitStatusCoordinator()
	return newExecSyscallOutput(ExecSyscallOutputDeps{
		Opts:              s.opts,
		State:             s.traceState(),
		Renderer:          s.textRenderer(),
		DiscardExitStatus: exitStatus.Discard,
	})
}

// IMPACT: Handle owns execve/execveat restart and superseded-thread text state.
func (o *ExecSyscallOutput) Handle(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result) bool {
	ev := syscallEventContext{
		raw:  eventRaw,
		view: newSyscallEventViewFromBPF(eventRaw),
		meta: scMeta,
	}
	return o.HandleEvent(ev, res)
}

// IMPACT: HandleEvent owns execve/execveat restart and superseded-thread text state from event context.
func (o *ExecSyscallOutput) HandleEvent(ev syscallEventContext, res handler.Result) bool {
	scMeta := ev.meta
	if !isExecSyscall(scMeta.Name) {
		return false
	}
	view := ev.eventView()
	tid := int(view.tid)
	tgid := int(view.pid)

	switch view.ret {
	case -514:
		o.rememberPendingArgs(tid, scMeta, res)
		if tid == tgid {
			return true
		}
		return o.handleNonLeaderRestart(ev, tid, scMeta, res)
	case 0:
		if tid == tgid {
			return o.handleLeaderSuccess(view, tid)
		}
		return o.handleNonLeaderSuccess(ev, tid, tgid, scMeta)
	default:
		return false
	}
}

func (o *ExecSyscallOutput) handleLeaderSuccess(view syscallEventView, tid int) bool {
	if o.state == nil {
		return true
	}
	argLine, ok := o.state.takePendingExecArgs(tid)
	if ok && o.renderer != nil {
		o.renderer.PrintExecResumeFromView(view, argLine)
	}
	return true
}

func (o *ExecSyscallOutput) handleNonLeaderRestart(ev syscallEventContext, tid int, scMeta meta.Syscall, res handler.Result) bool {
	if !o.followForks() {
		return false
	}
	view := ev.eventView()
	argLine := o.pendingArgLine(tid, scMeta, res)
	if view.probeRetEnter == 1 {
		o.renderer.PrintExecPidChangedFromView(view, argLine)
		return true
	}
	o.renderer.PrintExecSupersededUnfinishedFromView(view, argLine)
	return true
}

func (o *ExecSyscallOutput) handleNonLeaderSuccess(ev syscallEventContext, tid int, tgid int, scMeta meta.Syscall) bool {
	if !o.followForks() {
		return false
	}
	view := ev.eventView()
	if o.state != nil {
		o.state.deletePendingExecArgs(tid)
	}
	if o.discardExitStatus != nil {
		o.discardExitStatus(tgid)
	}
	if view.probeRetEnter == 1 {
		return true
	}
	if view.probeRetExit > 0 && o.state != nil {
		suspendedSysID := uint32(view.probeRetExit)
		if suspMeta, ok := meta.SyscallTable[suspendedSysID]; ok {
			o.state.deleteSuspendedSyscall(tgid)
			o.renderer.PrintSupersededSuspendedResumeFromView(view, suspMeta.Name)
		}
	}
	o.renderer.PrintThreadExecveSupersededFromView(view, scMeta.Name)
	return true
}

func (o *ExecSyscallOutput) rememberPendingArgs(tid int, scMeta meta.Syscall, res handler.Result) {
	if o.state == nil {
		return
	}
	o.state.rememberPendingExecArgs(tid, execArgLine(scMeta, res))
}

func (o *ExecSyscallOutput) pendingArgLine(tid int, scMeta meta.Syscall, res handler.Result) string {
	if o.state != nil {
		if argLine, ok := o.state.pendingExecArgsFor(tid); ok {
			return argLine
		}
	}
	return execArgLine(scMeta, res)
}

func (o *ExecSyscallOutput) followForks() bool {
	return o.opts != nil && o.opts.FollowForks && o.renderer != nil
}

func execArgLine(scMeta meta.Syscall, res handler.Result) string {
	return fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
}

func isExecSyscall(name string) bool {
	return name == "execve" || name == "execveat"
}
