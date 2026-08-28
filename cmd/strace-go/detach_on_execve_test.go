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
	if !next.detached || !policy.Reached() {
		t.Fatal("command did not detach on the next successful exec")
	}
}

func TestDetachOnExecveAttachStopsOnFirstSuccessfulExec(t *testing.T) {
	policy := newTraceDetachOnExecve(true, false)

	event := policy.Observe(detachExecEvent("execve", 0))
	if !event.detached || !policy.Reached() {
		t.Fatal("attach policy did not detach on the first successful exec")
	}
}

func TestDetachOnExecveDisabledIgnoresExec(t *testing.T) {
	policy := newTraceDetachOnExecve(false, false)

	event := policy.Observe(detachExecEvent("execve", 0))
	if event.detached || policy.Enabled() || policy.Reached() {
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

	if len(sink.events) != 1 || !sink.events[0].detached {
		t.Fatalf("pipeline events = %+v, want one detached exec", sink.events)
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
