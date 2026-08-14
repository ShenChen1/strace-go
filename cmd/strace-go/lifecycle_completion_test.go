package main

import (
	"testing"
	"time"

	"strace-go/pkg/cli"
)

type fakeLifecycleCompletionReader struct {
	exited    bool
	observed  bool
	quiescent bool
}

func (r *fakeLifecycleCompletionReader) TargetLifecycleExited(uint32) (bool, error) {
	return r.exited, nil
}

func (r *fakeLifecycleCompletionReader) TargetLifecycleEventObserved(uint32) bool {
	return r.observed
}

func (r *fakeLifecycleCompletionReader) TargetLifecycleQuiescent(uint32) bool {
	return r.quiescent
}

func newLifecycleWaitState(reader *fakeLifecycleCompletionReader, clock *fakeTraceClock) traceRunState {
	return traceRunState{
		commandExited:        true,
		commandLifecycle:     reader,
		commandLifecycleDone: false,
		targetPID:            901,
		attachExited:         true,
		clock:                clock,
	}
}

func TestTraceRunStateWaitsForLifecycleEventAfterBPFFact(t *testing.T) {
	reader := &fakeLifecycleCompletionReader{exited: true, quiescent: true}
	clock := &fakeTraceClock{now: time.Unix(100, 0)}
	state := newLifecycleWaitState(reader, clock)

	if err := state.collect(nil); err != nil {
		t.Fatalf("collect() error = %v, want nil", err)
	}
	if state.done() {
		t.Fatal("run state completed from BPF fact before lifecycle event")
	}
	if state.lifecycleFallbackAt.IsZero() {
		t.Fatal("missing bounded lifecycle fallback deadline")
	}

	reader.observed = true
	if err := state.collect(nil); err != nil {
		t.Fatalf("collect() after lifecycle event error = %v", err)
	}
	if !state.done() {
		t.Fatal("run state did not complete after lifecycle event and quiescence")
	}
	if state.commandLifecycleFallback {
		t.Fatal("normal lifecycle event path entered fallback")
	}
}

func TestTraceRunStateUsesBoundedFallbackWhenLifecycleEventIsMissing(t *testing.T) {
	reader := &fakeLifecycleCompletionReader{exited: true, quiescent: true}
	clock := &fakeTraceClock{now: time.Unix(100, 0)}
	state := newLifecycleWaitState(reader, clock)

	if err := state.collect(nil); err != nil {
		t.Fatalf("initial collect() error = %v", err)
	}
	clock.now = clock.now.Add(traceExitLifecycleDrainGrace + time.Millisecond)
	if err := state.collect(nil); err != nil {
		t.Fatalf("fallback collect() error = %v", err)
	}
	if !state.done() || !state.commandLifecycleFallback {
		t.Fatalf("fallback state = %+v, want done with fallback", state)
	}
}

func TestTraceRunStateUsesBoundedFallbackWhenChildQuiescenceIsMissing(t *testing.T) {
	reader := &fakeLifecycleCompletionReader{observed: true, quiescent: false}
	clock := &fakeTraceClock{now: time.Unix(100, 0)}
	state := newLifecycleWaitState(reader, clock)

	if err := state.collect(nil); err != nil {
		t.Fatalf("initial collect() error = %v", err)
	}
	if state.done() {
		t.Fatal("run state completed while tracked child was active")
	}
	clock.now = state.lifecycleFallbackAt.Add(time.Millisecond)
	if err := state.collect(nil); err != nil {
		t.Fatalf("fallback collect() error = %v", err)
	}
	if !state.done() || !state.commandLifecycleFallback {
		t.Fatalf("child fallback state = %+v, want done with fallback", state)
	}
}

func TestTraceStateWaitsForTrackedChildAfterRootLifecycleExit(t *testing.T) {
	state := newTraceStateForSession(newTraceEventPolicy(&cli.Options{FollowForks: true}))
	state.setCommandTargetPID(900)
	state.handleEnvelope(lifecycleEnvelopeForTask(700, 700, lifecycleExit, 0, 0))
	if state.TargetLifecycleEventObserved(900) {
		t.Fatal("unrelated lifecycle event marked command target as observed")
	}
	state.handleEnvelope(lifecycleEnvelopeForTask(900, 900, lifecycleFork, 900, 901))
	state.handleEnvelope(lifecycleEnvelopeForTask(900, 900, lifecycleExit, 0, 0))

	if !state.TargetLifecycleEventObserved(900) {
		t.Fatal("root lifecycle event was not observed")
	}
	if state.TargetLifecycleQuiescent(900) {
		t.Fatal("root completion ignored active child task")
	}

	state.handleEnvelope(lifecycleEnvelopeForTask(901, 901, lifecycleExit, 0, 0))
	if !state.TargetLifecycleQuiescent(900) {
		t.Fatal("tracked child kept root non-quiescent after child exit")
	}
}

func TestTraceStateWaitsForLifecycleAfterTerminatingSyscall(t *testing.T) {
	state := newTraceStateForSession(newTraceEventPolicy(&cli.Options{FollowForks: true}))
	state.setCommandTargetPID(910)
	id := syscallIDByName(t, "exit_group")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        910,
		tid:        910,
		sysID:      id,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	}
	state.handleEnvelope(enter)
	exit := enter
	exit.eventType = bpfEventTypeExit
	exit.eventFlags = 0
	state.handleEnvelope(exit)

	if state.TargetLifecycleQuiescent(910) {
		t.Fatal("terminating syscall exit cleared lifecycle wait too early")
	}
	state.handleEnvelope(lifecycleEnvelopeForTask(910, 910, lifecycleExit, 0, 0))
	if !state.TargetLifecycleQuiescent(910) {
		t.Fatal("lifecycle exit did not clear terminating syscall wait")
	}
}

func TestTraceSessionUsesFallbackDrainGraceOnlyForFallback(t *testing.T) {
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{})
	normal := traceRunState{commandLifecycleDone: true, commandLifecycleObserved: true}
	fallback := traceRunState{commandLifecycleDone: true, commandLifecycleFallback: true}

	if got := session.exitDrainGraceForState(normal); got != 0 {
		t.Fatalf("normal lifecycle drain grace = %s, want 0", got)
	}
	if got := session.exitDrainGraceForState(fallback); got != traceExitLifecycleDrainGrace {
		t.Fatalf("fallback lifecycle drain grace = %s, want %s", got, traceExitLifecycleDrainGrace)
	}
}
