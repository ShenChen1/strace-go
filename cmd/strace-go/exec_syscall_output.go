package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type ExecSyscallOutput struct {
	policy            traceFollowForkPolicy
	state             execSyscallState
	renderer          execSyscallRenderer
	discardExitStatus func(int)
}

type ExecSyscallOutputDeps struct {
	Policy            traceFollowForkPolicy
	State             execSyscallState
	Renderer          execSyscallRenderer
	DiscardExitStatus func(int)
}

func newExecSyscallOutput(deps ExecSyscallOutputDeps) *ExecSyscallOutput {
	return &ExecSyscallOutput{
		policy:            deps.Policy,
		state:             deps.State,
		renderer:          deps.Renderer,
		discardExitStatus: deps.DiscardExitStatus,
	}
}

// IMPACT: HandleEvent owns execve/execveat restart and superseded-thread text state from event context.
func (o *ExecSyscallOutput) HandleEvent(ev syscallEventContext, res handler.Result) bool {
	scMeta := ev.effectiveSyscallMeta()
	if !isExecSyscall(scMeta.Name) {
		return false
	}
	view := ev.eventView()
	tid := int(view.tid)
	tgid := int(view.pid)
	if ev.detached {
		return o.handleDetached(ev, tid, scMeta, res)
	}

	switch view.ret {
	case -514:
		o.rememberPendingArgs(tid, scMeta, res)
		if tid == tgid {
			return true
		}
		return o.handleNonLeaderRestart(ev, tid, scMeta, res)
	case 0:
		if tid == tgid {
			return o.handleLeaderSuccess(ev, tid, res)
		}
		return o.handleNonLeaderSuccess(ev, tid, tgid, scMeta)
	default:
		if o.state != nil {
			o.state.deletePendingExecArgs(tid)
		}
		return false
	}
}

func (o *ExecSyscallOutput) handleDetached(ev syscallEventContext, tid int, scMeta meta.Syscall, res handler.Result) bool {
	view := ev.eventView()
	argLine := execArgLine(scMeta, res, o.argNames())
	if o.state != nil {
		if pending, ok := o.state.takePendingExecArgs(tid); ok {
			argLine = pending
		}
	}
	if int(view.pid) != tid && o.followForks() {
		if o.discardExitStatus != nil {
			o.discardExitStatus(int(view.pid))
		}
		o.renderer.PrintExecPidChangedFromView(view, argLine)
		o.renderer.PrintExecDetachedThreadSupersededFromView(view)
		return true
	}
	if o.renderer != nil {
		o.renderer.PrintExecDetachedFromView(view, argLine)
	}
	return true
}

func (o *ExecSyscallOutput) handleLeaderSuccess(ev syscallEventContext, tid int, res handler.Result) bool {
	if o.state == nil {
		if o.renderer != nil {
			o.renderer.PrintSyscallEvent(ev, res)
		}
		return true
	}
	argLine, ok := o.state.takePendingExecArgs(tid)
	if ok && o.renderer != nil {
		o.renderer.PrintExecResumeFromView(ev.eventView(), argLine)
		return true
	}
	if !ok && o.renderer != nil {
		// The restart marker can arrive after the successful exit on another CPU.
		// The exit snapshot is already self-contained, so render it directly.
		o.renderer.PrintSyscallEvent(ev, res)
	}
	return true
}

func (o *ExecSyscallOutput) handleNonLeaderRestart(ev syscallEventContext, tid int, scMeta meta.Syscall, res handler.Result) bool {
	if !o.followForks() {
		if o.state != nil {
			o.state.deletePendingExecArgs(tid)
		}
		return false
	}
	if ev.pendingEnter != nil && ev.pendingEnter.unfinishedPrinted {
		return true
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
	o.state.rememberPendingExecArgs(tid, execArgLine(scMeta, res, o.argNames()))
}

func (o *ExecSyscallOutput) pendingArgLine(tid int, scMeta meta.Syscall, res handler.Result) string {
	if o.state != nil {
		if argLine, ok := o.state.pendingExecArgsFor(tid); ok {
			return argLine
		}
	}
	return execArgLine(scMeta, res, o.argNames())
}

func (o *ExecSyscallOutput) followForks() bool {
	return o.policy != nil && o.policy.FollowForks() && o.renderer != nil
}

func (o *ExecSyscallOutput) argNames() bool {
	return o.policy != nil && o.policy.ArgNames()
}

func execArgLine(scMeta meta.Syscall, res handler.Result, showArgNames bool) string {
	return fmt.Sprintf("%s(%s)", scMeta.Name, formatSyscallArguments(scMeta.Args, res.ArgParts, showArgNames))
}

func isExecSyscall(name string) bool {
	return name == "execve" || name == "execveat"
}
