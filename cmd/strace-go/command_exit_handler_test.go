package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceCommandExitHandlerFlushesTextFallback(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{EventFormat: cli.EventFormatText}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Policy:     newTraceOutputPolicy(opts),
		TargetPID:  101,
		ExitStatus: coordinator,
		Renderer:   newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts)}),
	})

	handler.MarkExited(traceCommandExitResult{exited: true, exitCode: 7})
	if output.Len() != 0 {
		t.Fatalf("fallback printed before flush: %q", output.String())
	}
	handler.FlushFallback()
	if output.String() != "+++ exited with 7 +++\n" {
		t.Fatalf("fallback output = %q", output.String())
	}
}

func TestTraceCommandExitHandlerSuppressesFallbackForJSON(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{EventFormat: cli.EventFormatJSON}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Policy:     newTraceOutputPolicy(opts),
		TargetPID:  101,
		ExitStatus: coordinator,
	})

	handler.MarkExited(traceCommandExitResult{exited: true, exitCode: 7})
	handler.FlushFallback()
	if output.Len() != 0 {
		t.Fatalf("JSON fallback should be suppressed: %q", output.String())
	}
}

func TestTraceCommandExitHandlerHandlesUnknownWaitResult(t *testing.T) {
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{Queue: newExitStatusQueue()})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		TargetPID:  101,
		ExitStatus: coordinator,
	})

	handler.MarkExited(traceCommandExitResult{})
	if !coordinator.queue.HasExited(101) {
		t.Fatal("unknown wait result should still release exit-status coordination")
	}
}
