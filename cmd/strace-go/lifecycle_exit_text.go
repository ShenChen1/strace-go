package main

import (
	"fmt"
	"io"
)

type traceLifecycleExitTextPort interface {
	WriteExitText(tid int, exitCode uint64)
}

type traceLifecycleExitTextWriter struct {
	policy     traceExitPolicy
	hasCommand bool
	targetPID  int
	out        io.Writer
	renderer   traceExitStatusLinePort
}

type traceLifecycleExitTextWriterDeps struct {
	Policy     traceExitPolicy
	HasCommand bool
	TargetPID  int
	Out        io.Writer
	Renderer   traceExitStatusLinePort
}

func newTraceLifecycleExitTextWriter(deps traceLifecycleExitTextWriterDeps) *traceLifecycleExitTextWriter {
	return &traceLifecycleExitTextWriter{
		policy:     deps.Policy,
		hasCommand: deps.HasCommand,
		targetPID:  deps.TargetPID,
		out:        deps.Out,
		renderer:   deps.Renderer,
	}
}

func (w *traceLifecycleExitTextWriter) WriteExitText(tid int, exitCode uint64) {
	if w == nil || w.policy == nil || w.policy.QuietExit() || w.policy.SummaryOnly() || w.policy.IsJSON() {
		return
	}
	if w.hasCommand && tid == w.targetPID {
		return
	}
	if w.out == nil || w.renderer == nil {
		return
	}
	fmt.Fprint(w.out, w.renderer.ExitStatusLine(tid, exitCode))
}

var _ traceLifecycleExitTextPort = (*traceLifecycleExitTextWriter)(nil)
