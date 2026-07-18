package main

import "strace-go/pkg/cli"

type LifecycleEventHandler struct {
	opts      *cli.Options
	inherit   func(parentPID int, childPID int)
	cleanup   func(pid int)
	writeJSON func(traceStateEventView, *TaskState)
}

type LifecycleEventHandlerDeps struct {
	Opts      *cli.Options
	Inherit   func(parentPID int, childPID int)
	Cleanup   func(pid int)
	WriteJSON func(traceStateEventView, *TaskState)
}

func newLifecycleEventHandler(deps LifecycleEventHandlerDeps) *LifecycleEventHandler {
	return &LifecycleEventHandler{
		opts:      deps.Opts,
		inherit:   deps.Inherit,
		cleanup:   deps.Cleanup,
		writeJSON: deps.WriteJSON,
	}
}

func (s *traceSession) lifecycleEventHandler() *LifecycleEventHandler {
	if s.lifecycleHandlerCache == nil {
		s.lifecycleHandlerCache = newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Opts:      s.opts,
			Inherit:   s.inheritProcessState,
			Cleanup:   s.cleanupProcessState,
			WriteJSON: s.writeJSONLifecycleEventView,
		})
	}
	return s.lifecycleHandlerCache
}

// IMPACT: Handle owns lifecycle side effects after TraceState has updated task state.
func (h *LifecycleEventHandler) Handle(view traceStateEventView, task *TaskState) {
	if view.lifecycleAction == lifecycleFork {
		h.inheritProcess(view)
	}
	switch view.lifecycleAction {
	case lifecycleExit, lifecycleFree:
		h.cleanupProcess(view)
	}
	if h.jsonMode() {
		h.writeLifecycleJSON(view, task)
	}
}

func (h *LifecycleEventHandler) inheritProcess(view traceStateEventView) {
	if h.inherit != nil {
		h.inherit(int(view.args[0]), int(view.args[1]))
	}
}

func (h *LifecycleEventHandler) cleanupProcess(view traceStateEventView) {
	if h.cleanup != nil {
		h.cleanup(int(view.tid))
	}
}

func (h *LifecycleEventHandler) writeLifecycleJSON(view traceStateEventView, task *TaskState) {
	if h.writeJSON != nil {
		h.writeJSON(view, task)
	}
}

func (h *LifecycleEventHandler) jsonMode() bool {
	return h.opts != nil && h.opts.EventFormat == cli.EventFormatJSON
}
