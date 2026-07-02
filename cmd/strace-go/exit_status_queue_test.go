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
	if !ok || line != "exited\n" {
		t.Fatalf("MarkExited after Queue = (%q, %v), want queued line", line, ok)
	}
}

func TestExitStatusQueueHandlesWaitBeforeRingEvent(t *testing.T) {
	queue := newExitStatusQueue()

	if line, ok := queue.MarkExited(101); ok || line != "" {
		t.Fatalf("MarkExited before Queue = (%q, %v), want no output", line, ok)
	}
	line, ok := queue.Queue(101, "exited\n")
	if !ok || line != "exited\n" {
		t.Fatalf("Queue after MarkExited = (%q, %v), want immediate line", line, ok)
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
	if output.String() != "exited\n" {
		t.Fatalf("exit status output = %q", output.String())
	}
}
