package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestDetachOnExecveCommandSkipsInitialSuccessfulExec(t *testing.T) {
	policy := newTraceDetachOnExecve(true, true)

	initial := policy.Observe(detachExecEvent("execve", 0))
	if initial.detached || policy.Reached() {
		t.Fatal("command detached on its initial successful exec")
	}
	failed := policy.Observe(detachExecEvent("execve", -2))
	if failed.detached || policy.Reached() {
		t.Fatal("command detached on a failed exec")
	}
	next := policy.Observe(detachExecEvent("execveat", 0))
	if !next.detached || !next.detachedByExecPolicy || !policy.Reached() {
		t.Fatal("command did not detach on the next successful exec")
	}
}

func TestDetachOnExecveLifecycleHandlesMissingInitialExit(t *testing.T) {
	policy := newTraceDetachOnExecve(true, true)
	initialLifecycle := lifecycleEventView{action: lifecycleExec, pid: 200, tid: 200}
	secondLifecycle := lifecycleEventView{action: lifecycleExec, pid: 200, tid: 200}

	policy.ObserveLifecycle(initialLifecycle)
	policy.ObserveLifecycle(secondLifecycle)
	second := policy.Observe(detachExecEvent("execve", 0))
	if !second.detached || !second.detachedByExecPolicy || !policy.Reached() {
		t.Fatal("missing initial syscall exit caused the second exec to be skipped")
	}
}

func TestDetachOnExecveLifecycleMatchesInitialExit(t *testing.T) {
	policy := newTraceDetachOnExecve(true, true)
	policy.ObserveLifecycle(lifecycleEventView{action: lifecycleExec, pid: 200, tid: 200, enterTime: 100})
	initial := detachExecEvent("execve", 0)
	initial.view.pid = 200
	initial.view.tid = 200
	initial.view.enterTime = 90

	initial = policy.Observe(initial)
	if initial.detached || policy.Reached() {
		t.Fatal("initial exec completion was not matched to its lifecycle event")
	}
	secondEvent := initial
	secondEvent.view.enterTime = 200
	second := policy.Observe(secondEvent)
	if !second.detached || !second.detachedByExecPolicy || !policy.Reached() {
		t.Fatal("second exec was skipped after matching the initial completion")
	}
}

func TestDetachOnExecveRecognizesNextExitBeforeNextLifecycle(t *testing.T) {
	policy := newTraceDetachOnExecve(true, true)
	policy.ObserveLifecycle(lifecycleEventView{action: lifecycleExec, pid: 200, tid: 200, enterTime: 100})
	next := detachExecEvent("execve", 0)
	next.view.pid = 200
	next.view.tid = 200
	next.view.enterTime = 200

	next = policy.Observe(next)
	if !next.detached || !next.detachedByExecPolicy || !policy.Reached() {
		t.Fatal("later exec exit was mistaken for a delayed initial completion")
	}
}

func TestDetachOnExecveAttachStopsOnFirstSuccessfulExec(t *testing.T) {
	policy := newTraceDetachOnExecve(true, false)

	event := policy.Observe(detachExecEvent("execve", 0))
	if !event.detached || !event.detachedByExecPolicy || !policy.Reached() {
		t.Fatal("attach policy did not detach on the first successful exec")
	}
}

func TestDetachOnExecveNonLeaderKeepsReplacementLeaderTracked(t *testing.T) {
	policy := newTraceDetachOnExecve(true, false)
	event := detachExecEvent("execve", 0)
	event.view.pid = 200
	event.view.tid = 201

	event = policy.Observe(event)
	if !event.detached || !event.detachedByExecPolicy {
		t.Fatal("non-leader exec was not classified as detached")
	}
	if policy.Reached() {
		t.Fatal("non-leader exec ended the session while the replacement leader remains tracked")
	}
}

func TestDetachOnExecveDisabledIgnoresExec(t *testing.T) {
	policy := newTraceDetachOnExecve(false, false)

	event := policy.Observe(detachExecEvent("execve", 0))
	if event.detached || event.detachedByExecPolicy || policy.Enabled() || policy.Reached() {
		t.Fatal("disabled detach policy changed session state")
	}
}

func TestDetachedStatusIsDistinctFromSuccessfulAndFailed(t *testing.T) {
	event := detachExecEvent("execve", 0)
	event.detached = true

	if !event.shouldEmitStatus(successfulFailedOptions{traceStatus: map[string]bool{"detached": true}}) {
		t.Fatal("status=detached rejected a detached exec")
	}
	for _, status := range []successfulFailedOptions{
		{successfulOnly: true},
		{failedOnly: true},
		{traceStatus: map[string]bool{"successful": true}},
		{traceStatus: map[string]bool{"failed": true}},
	} {
		if event.shouldEmitStatus(status) {
			t.Fatalf("detached exec matched non-detached status %+v", status)
		}
	}
}

func TestDetachOnExecveMarksEventBeforeExitPipeline(t *testing.T) {
	sink := &capturingDetachExitSink{}
	dispatcher := newTraceEventDispatcher(TraceEventDispatcherDeps{
		State:          newTraceState(),
		Pipeline:       sink,
		DetachOnExecve: newTraceDetachOnExecve(true, false),
		ContextDeps: syscallEventContextDeps{
			syscallMetadata: newSyscallMetadataTable(meta.SyscallTable),
		},
	})
	dispatcher.handleExit(TraceStateUpdate{
		syscallView: syscallEventView{
			valid: true,
			sysID: syscallIDByName(t, "execve"),
			ret:   0,
		},
	}, 101)

	if len(sink.events) != 1 || !sink.events[0].detached || !sink.events[0].detachedByExecPolicy {
		t.Fatalf("pipeline events = %+v, want one detached exec", sink.events)
	}
}

func TestNonLeaderExecHasDetachedStatusWithoutDetachOption(t *testing.T) {
	sink := &capturingDetachExitSink{}
	dispatcher := newTraceEventDispatcher(TraceEventDispatcherDeps{
		State:    newTraceState(),
		Pipeline: sink,
		ContextDeps: syscallEventContextDeps{
			syscallMetadata: newSyscallMetadataTable(meta.SyscallTable),
		},
	})
	dispatcher.handleExit(TraceStateUpdate{
		syscallView: syscallEventView{
			valid: true,
			pid:   200,
			tid:   201,
			sysID: syscallIDByName(t, "execve"),
			ret:   0,
		},
	}, 200)

	if len(sink.events) != 1 || !sink.events[0].detached ||
		sink.events[0].detachedByExecPolicy || sink.events[0].detachedByStatus {
		t.Fatalf("non-leader pipeline events = %+v, want detached status", sink.events)
	}
}

func TestDetachOnExecveSessionUsesSingleRecordBatches(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{DetachOnExecve: true})
	if got := session.eventBatchLimit(); got != 1 {
		t.Fatalf("detach session event batch = %d, want 1", got)
	}
}

func TestTraceSessionConfigSnapshotsDetachOnExecve(t *testing.T) {
	opts := &cli.Options{DetachOnExecve: true}
	config := newTraceSessionConfig(opts)
	opts.DetachOnExecve = false

	if !config.detachOnExecve {
		t.Fatal("session config did not retain detach-on-exec snapshot")
	}
}

func detachExecEvent(name string, ret int64) syscallEventContext {
	return syscallEventContext{
		view:        syscallEventView{valid: true, ret: ret},
		meta:        meta.Syscall{Name: name},
		shouldPrint: true,
	}
}

type capturingDetachExitSink struct {
	events []syscallEventContext
}

func (s *capturingDetachExitSink) Handle(event syscallEventContext) {
	s.events = append(s.events, event)
}

func (*capturingDetachExitSink) HandleUnfinished(syscallEventContext) bool { return false }

func (*capturingDetachExitSink) HasTextOutput() bool { return true }
