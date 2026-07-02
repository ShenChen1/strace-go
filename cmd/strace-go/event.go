package main

import (
	"fmt"

	"strace-go/pkg/cli"
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
	if !s.traceScope().Allows(eventRaw) {
		return
	}
	statePID := s.eventStatePID(eventRaw)
	stateUpdate := s.traceState().Handle(eventRaw)

	if stateUpdate.kind == traceStateLifecycle {
		s.handleLifecycleEvent(eventRaw, stateUpdate.lifecycleTask)
		return
	}

	scMeta := syscallMeta(eventRaw.SysId)

	if stateUpdate.kind == traceStateSyscallEnter {
		s.syscallJSONOutput().HandleEnter(eventRaw, scMeta, statePID)
		return
	}
	ev := newSyscallEventContext(s, eventRaw, statePID, stateUpdate.pendingEnter)

	scMeta = ev.meta

	defer func() {
		s.cleanupClosedFD(ev)
	}()
	defer s.updateFDOffsets(eventRaw, scMeta)

	if s.syscallJSONOutput().HandleDebugRaw(eventRaw, scMeta) {
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

	if s.exitSyscallOutput().Handle(ev) {
		return
	}

	res, shouldOutput := s.syscallHandlerRunner().Handle(ev)
	if !shouldOutput {
		return
	}

	if s.syscallJSONOutput().HandleDecoded(ev, res) {
		return
	}

	s.syscallTextOutput().Handle(ev.handlerContext, eventRaw, res)
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
