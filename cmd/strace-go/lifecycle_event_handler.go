package main

import "strace-go/pkg/cli"

type LifecycleEventHandler struct {
	opts      *cli.Options
	inherit   func(parentPID int, childPID int)
	cleanup   func(pid int)
	writeJSON func(*bpfEvent, *TaskState)
}

type LifecycleEventHandlerDeps struct {
	Opts      *cli.Options
	Inherit   func(parentPID int, childPID int)
	Cleanup   func(pid int)
	WriteJSON func(*bpfEvent, *TaskState)
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
	return newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Opts:      s.opts,
		Inherit:   s.inheritProcessState,
		Cleanup:   s.cleanupProcessState,
		WriteJSON: s.writeJSONLifecycleEvent,
	})
}

// IMPACT: Handle owns lifecycle side effects after TraceState has updated task state.
func (h *LifecycleEventHandler) Handle(eventRaw *bpfEvent, task *TaskState) {
	if eventRaw.EventFlags == lifecycleFork {
		h.inheritProcess(eventRaw)
	}
	switch eventRaw.EventFlags {
	case lifecycleExit, lifecycleFree:
		h.cleanupProcess(eventRaw)
	}
	if h.jsonMode() {
		h.writeLifecycleJSON(eventRaw, task)
	}
}

func (h *LifecycleEventHandler) inheritProcess(eventRaw *bpfEvent) {
	if h.inherit != nil {
		h.inherit(int(eventRaw.Args[0]), int(eventRaw.Args[1]))
	}
}

func (h *LifecycleEventHandler) cleanupProcess(eventRaw *bpfEvent) {
	if h.cleanup != nil {
		h.cleanup(int(eventRaw.Tid))
	}
}

func (h *LifecycleEventHandler) writeLifecycleJSON(eventRaw *bpfEvent, task *TaskState) {
	if h.writeJSON != nil {
		h.writeJSON(eventRaw, task)
	}
}

func (h *LifecycleEventHandler) jsonMode() bool {
	return h.opts != nil && h.opts.EventFormat == cli.EventFormatJSON
}
