package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestSyscallLimitCountsOnlyPublishableCompletedSyscalls(t *testing.T) {
	policy := newTraceOutputPolicy(&cli.Options{FailedOnly: true})
	limit := newTraceSyscallLimit(2, policy)

	limit.Observe(syscallLimitEvent(true, -2))
	if limit.Reached() {
		t.Fatal("limit reached after the first matching syscall")
	}
	limit.Observe(syscallLimitEvent(true, 0))
	limit.Observe(syscallLimitEvent(false, -2))
	if limit.Remaining() != 1 {
		t.Fatalf("remaining limit = %d, want 1 after filtered syscalls", limit.Remaining())
	}
	limit.Observe(syscallLimitEvent(true, -2))
	if !limit.Reached() {
		t.Fatal("limit was not reached after the second matching syscall")
	}
}

func TestSyscallLimitDisabledAtZero(t *testing.T) {
	limit := newTraceSyscallLimit(0, newTraceOutputPolicy(&cli.Options{}))

	limit.Observe(syscallLimitEvent(true, 0))
	if limit.Enabled() || limit.Reached() {
		t.Fatalf("zero limit = enabled:%v reached:%v, want false/false", limit.Enabled(), limit.Reached())
	}
}

func TestSessionSyscallLimitUsesSingleRecordBatches(t *testing.T) {
	limited := newTestTraceSession(traceSessionDeps{SyscallLimit: 3})
	if got := limited.eventBatchLimit(); got != 1 {
		t.Fatalf("limited event batch = %d, want 1", got)
	}

	unlimited := newTestTraceSessionWithOptions(&cli.Options{}, traceSessionDeps{})
	if got := unlimited.eventBatchLimit(); got != traceEventBatchLimit {
		t.Fatalf("unlimited event batch = %d, want %d", got, traceEventBatchLimit)
	}
}

func TestTraceSessionConfigSnapshotsSyscallLimit(t *testing.T) {
	opts := &cli.Options{SyscallLimit: 9}
	config := newTraceSessionConfig(opts)
	opts.SyscallLimit = 1

	if config.syscallLimit != 9 {
		t.Fatalf("config syscall limit = %d, want immutable snapshot 9", config.syscallLimit)
	}
}

func syscallLimitEvent(shouldPrint bool, ret int64) syscallEventContext {
	return syscallEventContext{
		view:        syscallEventView{valid: true, ret: ret},
		meta:        meta.Syscall{Name: "chdir"},
		shouldPrint: shouldPrint,
	}
}
