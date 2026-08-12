package main

import (
	"os/exec"
	"testing"
)

func TestTraceTargetRuntimeAbortBeforeExitPublishesOneResult(t *testing.T) {
	command := exec.Command("/bin/sleep", "10")
	if err := command.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	runtime := newTraceTargetRuntime(command)
	runtime.Abort()

	first := runtime.commandWaiter().Wait()
	second := runtime.commandWaiter().Wait()
	if first != second {
		t.Fatalf("completion result changed after abort: first=%+v second=%+v", first, second)
	}
	runtime.Abort()
}

func TestTraceTargetRuntimeRepeatedAbortAfterExitIsIdempotent(t *testing.T) {
	command := exec.Command("/bin/true")
	if err := command.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	runtime := newTraceTargetRuntime(command)
	want := runtime.commandWaiter().Wait()

	runtime.Abort()
	runtime.Abort()
	if got := runtime.commandWaiter().Wait(); got != want {
		t.Fatalf("cached completion result = %+v, want %+v", got, want)
	}
}

func TestTraceTargetRuntimeNilPortsAreInert(t *testing.T) {
	var runtime *traceTargetRuntime
	if runtime.commandWaiter() != nil {
		t.Fatal("nil target runtime returned a command waiter")
	}
	runtime.Abort()
}

func TestTraceSessionRejectsMismatchedCommandLifecyclePorts(t *testing.T) {
	deps := withTestTraceSessionDefaults(traceSessionDeps{HasCommand: true})
	if _, err := newTraceSession(deps); err == nil {
		t.Fatal("newTraceSession() accepted command without completion waiter")
	}
}
