package main

import "strace-go/pkg/cli"

// TraceCommandExitHandler translates command wait completion into exit-status
// queue effects. It deliberately does not own ringbuf reading or trace state.
type TraceCommandExitHandler struct {
	opts       *cli.Options
	targetPID  int
	exitStatus *ExitStatusCoordinator
	renderer   *TextRenderer
}

type TraceCommandExitHandlerDeps struct {
	Opts       *cli.Options
	TargetPID  int
	ExitStatus *ExitStatusCoordinator
	Renderer   *TextRenderer
}

func newTraceCommandExitHandler(deps TraceCommandExitHandlerDeps) *TraceCommandExitHandler {
	return &TraceCommandExitHandler{
		opts:       deps.Opts,
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
	if h == nil || !result.exited || h.opts == nil {
		return ""
	}
	if h.opts.QuietExit || h.opts.SummaryOnly || h.opts.EventFormat == cli.EventFormatJSON {
		return ""
	}
	if h.renderer == nil {
		return ""
	}
	return h.renderer.ExitStatusLine(h.targetPID, result.exitCode)
}
