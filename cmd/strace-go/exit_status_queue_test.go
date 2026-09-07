package main

import (
	"bytes"
	"testing"
)

func TestExitStatusQueueWaitsForProcessExit(t *testing.T) {
	queue := newExitStatusQueue()

	if line, ok := queue.Queue(101, "exited\n"); ok || line != "" {
		t.Fatalf("Queue before MarkExited = (%q, %v), want no output", line, ok)
	}
	line, ok := queue.MarkExited(101)
	if ok || line != "" {
		t.Fatalf("MarkExited after Queue = (%q, %v), want deferred output", line, ok)
	}
	line, ok = queue.FlushFallback(101)
	if !ok || line != "exited\n" {
		t.Fatalf("FlushFallback after Queue = (%q, %v), want queued line", line, ok)
	}
}

func TestExitStatusQueueHandlesWaitBeforeRingEvent(t *testing.T) {
	queue := newExitStatusQueue()

	if line, ok := queue.MarkExited(101); ok || line != "" {
		t.Fatalf("MarkExited before Queue = (%q, %v), want no output", line, ok)
	}
	line, ok := queue.Queue(101, "exited\n")
	if ok || line != "" {
		t.Fatalf("Queue after MarkExited = (%q, %v), want deferred output", line, ok)
	}
	line, ok = queue.FlushFallback(101)
	if !ok || line != "exited\n" {
		t.Fatalf("FlushFallback after MarkExited = (%q, %v), want queued line", line, ok)
	}
}

func TestExitStatusQueueFlushesWaitFallback(t *testing.T) {
	queue := newExitStatusQueue()

	if line, ok := queue.MarkExitedWithFallback(101, "fallback\n"); ok || line != "" {
		t.Fatalf("MarkExitedWithFallback = (%q, %v), want no immediate output", line, ok)
	}
	line, ok := queue.FlushFallback(101)
	if !ok || line != "fallback\n" {
		t.Fatalf("FlushFallback = (%q, %v), want fallback line", line, ok)
	}
	if line, ok := queue.FlushFallback(101); ok || line != "" {
		t.Fatalf("second FlushFallback = (%q, %v), want no output", line, ok)
	}
}

func TestExitStatusQueuePrefersRingEventOverWaitFallback(t *testing.T) {
	queue := newExitStatusQueue()

	queue.MarkExitedWithFallback(101, "fallback\n")
	line, ok := queue.Queue(101, "ring\n")
	if ok || line != "" {
		t.Fatalf("Queue after fallback = (%q, %v), want deferred output", line, ok)
	}
	if line, ok := queue.FlushFallback(101); !ok || line != "ring\n" {
		t.Fatalf("FlushFallback after ring line = (%q, %v), want ring line", line, ok)
	}
}

func TestExitStatusQueueDiscardDropsPendingAndExitedState(t *testing.T) {
	queue := newExitStatusQueue()

	queue.Queue(101, "wrong exit\n")
	queue.MarkExited(102)
	queue.Discard(101)
	queue.Discard(102)

	if line, ok := queue.Queue(102, "final exit\n"); ok || line != "" {
		t.Fatalf("Queue after discard = (%q, %v), want no output", line, ok)
	}
}

func TestTraceSessionExitStatusWritesQueuedLineAfterMark(t *testing.T) {
	var output bytes.Buffer
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})

	coordinator.Queue(101, "exited\n")
	if output.Len() != 0 {
		t.Fatalf("exit status printed before wait exit: %q", output.String())
	}
	coordinator.MarkExited(101)
	if output.Len() != 0 {
		t.Fatalf("exit status printed before drain: %q", output.String())
	}
	coordinator.FlushFallback(101)
	if output.String() != "exited\n" {
		t.Fatalf("exit status output after flush = %q", output.String())
	}
}

func TestTraceSessionExitStatusWritesFallbackAfterFlush(t *testing.T) {
	var output bytes.Buffer
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})

	coordinator.MarkExitedWithFallback(101, "fallback\n")
	if output.Len() != 0 {
		t.Fatalf("fallback printed before flush: %q", output.String())
	}
	coordinator.FlushFallback(101)
	if output.String() != "fallback\n" {
		t.Fatalf("fallback output = %q", output.String())
	}
}

func TestTraceSessionExitStatusFlushesAttachedCommandAtWait(t *testing.T) {
	var output bytes.Buffer
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue:      newExitStatusQueue(),
		Out:        &output,
		HasCommand: true,
		AttachPids: []int{202},
	})

	coordinator.Queue(101, "command exit\n")
	coordinator.MarkExitedWithFallback(101, "fallback exit\n")

	if got := output.String(); got != "command exit\n" {
		t.Fatalf("attached command exit output = %q, want queued command line", got)
	}
	coordinator.Queue(101, "late exit\n")
	if got := output.String(); got != "command exit\n" {
		t.Fatalf("late attached command exit output = %q, want no duplicate", got)
	}
}
