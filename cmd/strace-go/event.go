package main

import (
	"fmt"
	"strings"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// IMPACT: resolvePtrProbeRet returns the specific probe status for eventRaw.Ptr based on its argument index.
func resolvePtrProbeRet(eventRaw *bpfEvent) int32 {
	if eventRaw.Ptr == 0 {
		return 0
	}
	for i, val := range eventRaw.Args {
		if val == eventRaw.Ptr {
			return getArgProbeStatus(eventRaw.ProbeRetEnter, i)
		}
	}
	return eventRaw.ProbeRetEnter
}

// IMPACT: getArgProbeStatus decodes the bitmask for entry argument success flag.
func getArgProbeStatus(probeRetEnter int32, argIndex int) int32 {
	if probeRetEnter >= 0 {
		return 0
	}
	if probeRetEnter == -1 {
		return -1
	}
	mask := -probeRetEnter - 1
	if (mask & (1 << argIndex)) != 0 {
		return -2
	}
	return 0
}

// IMPACT: handleEvent parses, decodes, and routes tracing events to print handlers or fd updates.
func (s *traceSession) handleEvent(eventRaw *bpfEvent) {
	isAttached := false
	if s.opts != nil && len(s.opts.AttachPids) > 0 {
		for _, pid := range s.opts.AttachPids {
			if int(eventRaw.Pid) == pid {
				isAttached = true
				break
			}
		}
	} else if int(eventRaw.Pid) == s.targetPid {
		isAttached = true
	}

	if !isAttached {
		if s.opts == nil || !s.opts.FollowForks {
			return
		}
	}
	tPid := int(eventRaw.Tid)
	statePID := s.eventStatePID(eventRaw)
	stateUpdate := s.traceState().Handle(eventRaw)

	if stateUpdate.kind == traceStateLifecycle {
		s.handleLifecycleEvent(eventRaw, stateUpdate.lifecycleTask)
		return
	}

	scMeta := syscallMeta(eventRaw.SysId)

	if stateUpdate.kind == traceStateSyscallEnter {
		if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON &&
			(s.opts.DebugEvents || checkShouldPrint(eventRaw, scMeta, "", false, statePID, s.opts, s.fdStateStore().PathMap())) {
			s.writeJSONRawEvent(eventRaw, scMeta)
		}
		return
	}
	ev := newSyscallEventContext(s, eventRaw, statePID, stateUpdate.pendingEnter)

	scMeta = ev.meta

	defer func() {
		s.cleanupClosedFD(ev)
	}()
	defer s.updateFDOffsets(eventRaw, scMeta)

	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON && s.opts.DebugEvents {
		s.writeJSONRawEvent(eventRaw, scMeta)
		return
	}

	if scMeta.Name == "arch_prctl" && eventRaw.Args[0] == 0x1002 {
		return
	}

	if s.opts.SummaryOnly || s.opts.SummaryAndPrint {
		s.updateSummaryStats(ev)
		if s.opts.SummaryOnly {
			return
		}
	}

	ctx := ev.handlerContext

	if eventRaw.ProbeRetEnter == -1 && (scMeta.Name == "exit" || scMeta.Name == "exit_group") {
		if s.opts == nil || !s.opts.SummaryOnly {
			renderer := s.textRenderer()
			if ev.shouldPrint {
				h := handler.Get(scMeta.Name)
				res := h.Handle(ctx)
				if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
					s.writeJSONEvent(eventRaw, scMeta, res, ctx, ev.pendingEnter)
					return
				}
				renderer.PrintExitSyscall(eventRaw, scMeta, res)
			}
			if s.opts == nil || !s.opts.QuietExit {
				exitLine := renderer.ExitStatusLine(eventRaw)
				if s.shouldQueueExitStatus(int(eventRaw.Pid)) {
					s.queueExitStatus(tPid, exitLine)
				} else {
					fmt.Fprint(s.outWriter, exitLine)
				}
			}
		}
		return
	}

	if !ev.shouldPrint {
		if ev.isFDStateSyscall() {
			handler.Get(scMeta.Name).Handle(ctx)
		}
		s.updateFDState(ev)
		return
	}

	h := handler.Get(scMeta.Name)
	res := h.Handle(ctx)
	s.updateFDState(ev)

	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
		status := successfulFailedOptions{
			successfulOnly: s.opts.SuccessfulOnly,
			failedOnly:     s.opts.FailedOnly,
			traceStatus:    s.opts.TraceStatus,
		}
		if shouldEmitStatus(eventRaw, scMeta, status) {
			s.writeJSONEvent(eventRaw, scMeta, res, ctx, ev.pendingEnter)
		}
		return
	}

	s.handleEventOutput(ctx, eventRaw, res)
}

func (s *traceSession) handleLifecycleEvent(eventRaw *bpfEvent, task *TaskState) {
	if eventRaw.EventFlags == lifecycleFork {
		s.inheritProcessState(int(eventRaw.Args[0]), int(eventRaw.Args[1]))
	}
	switch eventRaw.EventFlags {
	case lifecycleExit, lifecycleFree:
		s.cleanupProcessState(int(eventRaw.Tid))
	}
	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
		s.writeJSONLifecycleEvent(eventRaw, task)
	}
}

// IMPACT: handleEventOutput handles specific unfinished states and delegates trace printing.
func (s *traceSession) handleEventOutput(ctx *handler.Context, eventRaw *bpfEvent, res handler.Result) {
	tPid := int(eventRaw.Tid)
	scMeta := ctx.ScMeta
	ret := eventRaw.Ret

	if s.opts != nil {
		status := successfulFailedOptions{
			successfulOnly: s.opts.SuccessfulOnly,
			failedOnly:     s.opts.FailedOnly,
			traceStatus:    s.opts.TraceStatus,
		}
		if !shouldEmitStatus(eventRaw, scMeta, status) {
			return
		}
	}

	if eventRaw.ProbeRetEnter == 3 {
		s.textRenderer().PrintUnfinished(eventRaw, scMeta, res)
		s.traceState().rememberSuspendedSyscall(tPid, scMeta.Name)
		return
	}

	if eventRaw.ProbeRetEnter == 2 {
		return
	}

	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == -514 {
		s.traceState().rememberPendingExecArgs(tPid, fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", ")))
		if tPid == int(eventRaw.Pid) {
			return
		}
	}

	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == 0 && tPid == int(eventRaw.Pid) {
		argLine, ok := s.traceState().takePendingExecArgs(tPid)
		if ok {
			s.textRenderer().PrintExecResume(eventRaw, argLine)
		}
		return
	}

	if handleSuperseded(eventRaw, scMeta, res, s) {
		return
	}

	s.textRenderer().PrintSyscall(eventRaw, scMeta, res, ctx)
}

// IMPACT: handleSuperseded formats and prints superseded thread details when a non-leader thread executes execve.
func handleSuperseded(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result, s *traceSession) bool {
	ret := eventRaw.Ret
	tPid := int(eventRaw.Tid)
	tgid := int(eventRaw.Pid)
	opts := s.opts
	renderer := s.textRenderer()
	isExecSuspended := (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == -514
	if isExecSuspended && tPid != tgid && opts != nil && opts.FollowForks {
		exited := eventRaw.ProbeRetEnter == 1

		argLine, ok := s.traceState().pendingExecArgsFor(tPid)
		if !ok {
			argLine = fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
		}

		if exited {
			renderer.PrintExecPidChanged(eventRaw, argLine)
		} else {
			renderer.PrintExecSupersededUnfinished(eventRaw, argLine)
		}
		return true
	}
	isExecSuccess := (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == 0
	if isExecSuccess && tPid != tgid && opts != nil && opts.FollowForks {
		exited := eventRaw.ProbeRetEnter == 1
		s.traceState().deletePendingExecArgs(tPid)
		s.discardExitStatus(tgid)

		if exited {
			return true
		}

		if eventRaw.ProbeRetExit > 0 {
			suspendedSysId := uint32(eventRaw.ProbeRetExit)
			if suspMeta, ok := meta.SyscallTable[suspendedSysId]; ok {
				s.traceState().deleteSuspendedSyscall(tgid)

				renderer.PrintSupersededSuspendedResume(eventRaw, suspMeta.Name)
			}
		}
		renderer.PrintThreadExecveSuperseded(eventRaw, scMeta.Name)
		return true
	}
	return false
}

func (s *traceSession) shouldQueueExitStatus(tgid int) bool {
	if s.cmd == nil {
		return false
	}
	if s.opts != nil {
		for _, pid := range s.opts.AttachPids {
			if pid == tgid {
				return false
			}
		}
	}
	return true
}

func (s *traceSession) queueExitStatus(pid int, line string) {
	if line, ok := s.exitStatusQueue().Queue(pid, line); ok {
		fmt.Fprint(s.outWriter, line)
		return
	}
}

func (s *traceSession) markTraceeExited(pid int) {
	if line, ok := s.exitStatusQueue().MarkExited(pid); ok {
		fmt.Fprint(s.outWriter, line)
		return
	}
}

func (s *traceSession) discardExitStatus(pid int) {
	s.exitStatusQueue().Discard(pid)
}
