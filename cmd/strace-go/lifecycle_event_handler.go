package main

import (
	"fmt"

	"strace-go/pkg/cli"
)

type LifecycleEventHandler struct {
	opts          *cli.Options
	inherit       func(parentPID int, childPID int)
	cleanup       func(pid int)
	writeJSON     func(lifecycleEventView, *TaskState)
	writeExitText func(tid int, exitCode uint64)
}

type LifecycleEventHandlerDeps struct {
	Opts          *cli.Options
	Inherit       func(parentPID int, childPID int)
	Cleanup       func(pid int)
	WriteJSON     func(lifecycleEventView, *TaskState)
	WriteExitText func(tid int, exitCode uint64)
}

func newLifecycleEventHandler(deps LifecycleEventHandlerDeps) *LifecycleEventHandler {
	return &LifecycleEventHandler{
		opts:          deps.Opts,
		inherit:       deps.Inherit,
		cleanup:       deps.Cleanup,
		writeJSON:     deps.WriteJSON,
		writeExitText: deps.WriteExitText,
	}
}

func (s *traceSession) lifecycleEventHandler() *LifecycleEventHandler {
	if s.lifecycleHandlerCache == nil {
		s.lifecycleHandlerCache = newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Opts:          s.opts,
			Inherit:       s.inheritProcessState,
			Cleanup:       s.cleanupProcessState,
			WriteJSON:     s.writeJSONLifecycleEventView,
			WriteExitText: s.writeLifecycleExitText,
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
		h.cleanupProcess(view)
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
		if !h.jsonMode() && h.writeExitText != nil &&
			(isAttachTarget || isThread || task != nil && task.Execed) {
			h.writeExitText(int(view.tid), view.args[0])
		}
	case lifecycleFree:
		h.cleanupProcess(view)
	}
	if h.jsonMode() {
		h.writeLifecycleJSON(view, task)
	}
}

func (h *LifecycleEventHandler) inheritProcess(view lifecycleEventView) {
	if h.inherit != nil {
		h.inherit(int(view.args[0]), int(view.args[1]))
	}
}

func (h *LifecycleEventHandler) cleanupProcess(view lifecycleEventView) {
	if h.cleanup != nil {
		h.cleanup(int(view.tid))
	}
}

func (h *LifecycleEventHandler) writeLifecycleJSON(view lifecycleEventView, task *TaskState) {
	if h.writeJSON != nil {
		h.writeJSON(view, task)
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
