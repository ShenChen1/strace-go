package main

// TraceCommandExitHandler translates command wait completion into exit-status
// queue effects. It deliberately does not own ringbuf reading or trace state.
type traceCommandExitStatusPort interface {
	MarkExitedWithFallback(pid int, fallback string)
	FlushFallback(pid int)
}

type traceExitStatusLinePort interface {
	ExitStatusLine(tid int, status uint64) string
	LifecycleExitStatusLine(tid int, rawStatus uint64) string
}

type TraceCommandExitHandler struct {
	policy     traceExitPolicy
	targetPID  int
	exitStatus traceCommandExitStatusPort
	renderer   traceExitStatusLinePort
}

type TraceCommandExitHandlerDeps struct {
	Policy     traceExitPolicy
	TargetPID  int
	ExitStatus traceCommandExitStatusPort
	Renderer   traceExitStatusLinePort
}

func newTraceCommandExitHandler(deps TraceCommandExitHandlerDeps) *TraceCommandExitHandler {
	return &TraceCommandExitHandler{
		policy:     deps.Policy,
		targetPID:  deps.TargetPID,
		exitStatus: deps.ExitStatus,
		renderer:   deps.Renderer,
	}
}

func (s *traceSession) commandExitHandler() *TraceCommandExitHandler {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.commandExitHandler
}

func (h *TraceCommandExitHandler) MarkExited(result traceCommandExitResult) {
	if h == nil || h.exitStatus == nil {
		return
	}
	h.exitStatus.MarkExitedWithFallback(h.targetPID, h.fallbackLine(result))
}

func (h *TraceCommandExitHandler) FlushFallback() {
	if h == nil || h.exitStatus == nil {
		return
	}
	h.exitStatus.FlushFallback(h.targetPID)
}

func (h *TraceCommandExitHandler) fallbackLine(result traceCommandExitResult) string {
	if h == nil || !result.exited || h.policy == nil {
		return ""
	}
	if h.policy.QuietExit() || h.policy.SummaryOnly() || h.policy.IsJSON() || h.policy.DiscardEvents() {
		return ""
	}
	if h.renderer == nil {
		return ""
	}
	return h.renderer.ExitStatusLine(h.targetPID, result.exitCode)
}
