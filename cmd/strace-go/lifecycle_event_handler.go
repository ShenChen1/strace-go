package main

import (
	"fmt"

	"strace-go/pkg/cli"
)

type LifecycleEventHandler struct {
	opts    *cli.Options
	effects LifecycleEffects
}

type LifecycleEventHandlerDeps struct {
	Opts    *cli.Options
	Effects LifecycleEffects
}

type LifecycleEffects interface {
	InheritProcessState(parentPID int, childPID int)
	CleanupProcessState(pid int)
	WriteJSON(lifecycleEventView, *TaskState)
	WriteExitText(tid int, exitCode uint64)
}

type traceSessionLifecycleEffects struct {
	fdState       *FDStateStore
	jsonWriter    jsonEventWriter
	writeExitText func(tid int, exitCode uint64)
}

func newTraceSessionLifecycleEffects(
	fdState *FDStateStore,
	jsonWriter jsonEventWriter,
	writeExitText func(tid int, exitCode uint64),
) *traceSessionLifecycleEffects {
	return &traceSessionLifecycleEffects{
		fdState:       fdState,
		jsonWriter:    jsonWriter,
		writeExitText: writeExitText,
	}
}

func (e *traceSessionLifecycleEffects) InheritProcessState(parentPID int, childPID int) {
	if e.fdState != nil {
		e.fdState.InheritProcessState(parentPID, childPID)
	}
}

func (e *traceSessionLifecycleEffects) CleanupProcessState(pid int) {
	if e.fdState != nil {
		e.fdState.CleanupProcess(pid)
	}
}

func (e *traceSessionLifecycleEffects) WriteJSON(view lifecycleEventView, task *TaskState) {
	if e.jsonWriter != nil {
		e.jsonWriter.WriteLifecycle(view, task)
	}
}

func (e *traceSessionLifecycleEffects) WriteExitText(tid int, exitCode uint64) {
	if e.writeExitText != nil {
		e.writeExitText(tid, exitCode)
	}
}

func newLifecycleEventHandler(deps LifecycleEventHandlerDeps) *LifecycleEventHandler {
	return &LifecycleEventHandler{
		opts:    deps.Opts,
		effects: deps.Effects,
	}
}

func (s *traceSession) lifecycleEventHandler() *LifecycleEventHandler {
	if s.lifecycleHandlerCache == nil {
		s.lifecycleHandlerCache = newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Opts: s.opts,
			Effects: newTraceSessionLifecycleEffects(
				s.fdStateStore(),
				s.jsonEventWriter(),
				s.writeLifecycleExitText,
			),
		})
	}
	return s.lifecycleHandlerCache
}

// IMPACT: Handle owns lifecycle side effects after TraceState has updated task state.
func (h *LifecycleEventHandler) Handle(view lifecycleEventView, task *TaskState) {
	if view.action == lifecycleFork {
		h.inheritProcess(view)
	}
	switch view.action {
	case lifecycleExit:
		h.cleanupProcess(view, task)
		isAttachTarget := false
		if h.opts != nil {
			for _, pid := range h.opts.AttachPids {
				if pid == int(view.tid) {
					isAttachTarget = true
					break
				}
			}
		}
		isThread := task != nil && task.TID != task.TGID
		if !h.jsonMode() &&
			(isAttachTarget || isThread || task != nil && task.Execed) {
			h.writeExitText(int(view.tid), view.args[0])
		}
	case lifecycleFree:
		h.cleanupProcess(view, task)
	}
	if h.jsonMode() {
		h.writeLifecycleJSON(view, task)
	}
}

func (h *LifecycleEventHandler) inheritProcess(view lifecycleEventView) {
	if h.effects != nil {
		h.effects.InheritProcessState(int(view.args[0]), int(view.args[1]))
	}
}

func (h *LifecycleEventHandler) cleanupProcess(view lifecycleEventView, task *TaskState) {
	if h.effects == nil {
		return
	}

	cleanupPID := int(view.tid)
	if task != nil && task.TID != 0 && task.TGID != 0 {
		if task.TID != task.TGID {
			return
		}
		cleanupPID = int(task.TGID)
	} else if view.pid != 0 && view.tid != 0 {
		if view.pid != view.tid {
			return
		}
		cleanupPID = int(view.pid)
	}

	h.effects.CleanupProcessState(cleanupPID)
}

func (h *LifecycleEventHandler) writeLifecycleJSON(view lifecycleEventView, task *TaskState) {
	if h.effects != nil {
		h.effects.WriteJSON(view, task)
	}
}

func (h *LifecycleEventHandler) writeExitText(tid int, exitCode uint64) {
	if h.effects != nil {
		h.effects.WriteExitText(tid, exitCode)
	}
}

// writeLifecycleExitText renders the "+++ exited with N +++" line for traced
// processes whose exit status is not owned by the command wait path (attached
// pids and follow-fork children). The command tracee's line is emitted by the
// ExitStatusCoordinator after the ringbuf drain to preserve wait ordering.
func (s *traceSession) writeLifecycleExitText(tid int, exitCode uint64) {
	if s == nil || s.opts == nil {
		return
	}
	if s.opts.QuietExit || s.opts.SummaryOnly || s.opts.EventFormat == cli.EventFormatJSON {
		return
	}
	if s.cmd != nil && tid == s.targetPid {
		return
	}
	fmt.Fprint(s.outWriter, s.textRenderer().ExitStatusLine(tid, exitCode))
}

func (h *LifecycleEventHandler) jsonMode() bool {
	return h.opts != nil && h.opts.EventFormat == cli.EventFormatJSON
}
