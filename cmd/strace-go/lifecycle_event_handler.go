package main

type LifecycleEventHandler struct {
	policy  traceLifecyclePolicy
	effects LifecycleEffects
}

type LifecycleEventHandlerDeps struct {
	Policy  traceLifecyclePolicy
	Effects LifecycleEffects
}

type LifecycleEffects interface {
	InheritProcessState(parentPID int, childPID int)
	CleanupProcessState(pid int)
	CloseOnExecState(pid int)
	WriteJSON(lifecycleEventView, *TaskState)
	WriteExitText(tid int, exitCode uint64)
}

type traceSessionLifecycleEffects struct {
	fdState    fdLifecycleUpdatePort
	jsonWriter jsonEventWriter
	exitText   traceLifecycleExitTextPort
}

func newTraceSessionLifecycleEffects(
	fdState fdLifecycleUpdatePort,
	jsonWriter jsonEventWriter,
	exitText traceLifecycleExitTextPort,
) *traceSessionLifecycleEffects {
	return &traceSessionLifecycleEffects{
		fdState:    fdState,
		jsonWriter: jsonWriter,
		exitText:   exitText,
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

func (e *traceSessionLifecycleEffects) CloseOnExecState(pid int) {
	if e.fdState != nil {
		e.fdState.CloseOnExecProcess(pid)
	}
}

func (e *traceSessionLifecycleEffects) WriteJSON(view lifecycleEventView, task *TaskState) {
	if e.jsonWriter != nil {
		e.jsonWriter.WriteLifecycle(view, task)
	}
}

func (e *traceSessionLifecycleEffects) WriteExitText(tid int, exitCode uint64) {
	if e.exitText != nil {
		e.exitText.WriteExitText(tid, exitCode)
	}
}

func newLifecycleEventHandler(deps LifecycleEventHandlerDeps) *LifecycleEventHandler {
	return &LifecycleEventHandler{
		policy:  deps.Policy,
		effects: deps.Effects,
	}
}

func (s *traceSession) lifecycleEventHandler() *LifecycleEventHandler {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.lifecycleHandler
}

// IMPACT: Handle owns lifecycle side effects after TraceState has updated task state.
func (h *LifecycleEventHandler) Handle(view lifecycleEventView, task *TaskState) {
	switch view.action {
	case lifecycleExec:
		h.closeOnExec(view, task)
	case lifecycleExit:
		h.cleanupProcess(view, task)
		isAttachTarget := h.policy != nil && h.policy.IsAttachTarget(int(view.tid))
		isKnownTask := task != nil && (task.Execed || task.ParentTID != 0 || task.TID != task.TGID)
		if !h.jsonMode() && !h.discardMode() && (isAttachTarget || isKnownTask) {
			h.writeExitText(int(view.tid), view.args[0])
		}
	case lifecycleFree:
		h.cleanupProcess(view, task)
	}
	if h.jsonMode() {
		h.writeLifecycleJSON(view, task)
	}
}

func (h *LifecycleEventHandler) closeOnExec(view lifecycleEventView, task *TaskState) {
	if h.effects == nil {
		return
	}
	pid := int(view.pid)
	if pid == 0 && task != nil {
		pid = int(task.TGID)
		if pid == 0 {
			pid = int(task.TID)
		}
	}
	if pid == 0 {
		pid = int(view.tid)
	}
	if pid > 0 {
		h.effects.CloseOnExecState(pid)
	}
}

func (h *LifecycleEventHandler) InheritProcessState(parentPID int, childPID int) {
	if h.effects != nil {
		h.effects.InheritProcessState(parentPID, childPID)
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

func (h *LifecycleEventHandler) jsonMode() bool {
	return h.policy != nil && h.policy.IsJSON()
}

func (h *LifecycleEventHandler) discardMode() bool {
	return h.policy != nil && h.policy.DiscardEvents()
}
