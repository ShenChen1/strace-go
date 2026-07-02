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
	if !isExecSyscall(scMeta.Name) {
		return false
	}
	tid := int(eventRaw.Tid)
	tgid := int(eventRaw.Pid)

	switch eventRaw.Ret {
	case -514:
		o.rememberPendingArgs(tid, scMeta, res)
		if tid == tgid {
			return true
		}
		return o.handleNonLeaderRestart(eventRaw, tid, scMeta, res)
	case 0:
		if tid == tgid {
			return o.handleLeaderSuccess(eventRaw, tid)
		}
		return o.handleNonLeaderSuccess(eventRaw, tid, tgid, scMeta)
	default:
		return false
	}
}

func (o *ExecSyscallOutput) handleLeaderSuccess(eventRaw *bpfEvent, tid int) bool {
	if o.state == nil {
		return true
	}
	argLine, ok := o.state.takePendingExecArgs(tid)
	if ok && o.renderer != nil {
		o.renderer.PrintExecResume(eventRaw, argLine)
	}
	return true
}

func (o *ExecSyscallOutput) handleNonLeaderRestart(eventRaw *bpfEvent, tid int, scMeta meta.Syscall, res handler.Result) bool {
	if !o.followForks() {
		return false
	}
	argLine := o.pendingArgLine(tid, scMeta, res)
	if eventRaw.ProbeRetEnter == 1 {
		o.renderer.PrintExecPidChanged(eventRaw, argLine)
		return true
	}
	o.renderer.PrintExecSupersededUnfinished(eventRaw, argLine)
	return true
}

func (o *ExecSyscallOutput) handleNonLeaderSuccess(eventRaw *bpfEvent, tid int, tgid int, scMeta meta.Syscall) bool {
	if !o.followForks() {
		return false
	}
	if o.state != nil {
		o.state.deletePendingExecArgs(tid)
	}
	if o.discardExitStatus != nil {
		o.discardExitStatus(tgid)
	}
	if eventRaw.ProbeRetEnter == 1 {
		return true
	}
	if eventRaw.ProbeRetExit > 0 && o.state != nil {
		suspendedSysID := uint32(eventRaw.ProbeRetExit)
		if suspMeta, ok := meta.SyscallTable[suspendedSysID]; ok {
			o.state.deleteSuspendedSyscall(tgid)
			o.renderer.PrintSupersededSuspendedResume(eventRaw, suspMeta.Name)
		}
	}
	o.renderer.PrintThreadExecveSuperseded(eventRaw, scMeta.Name)
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
