package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskLifecycleStateOwnershipBoundaries(t *testing.T) {
	root := repoRootForTest(t)
	stateSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_task_lifecycle.go"))
	attachPath := filepath.Join(root, "cmd/strace-go/event_attach_state.go")
	attachSource := readTextFile(t, attachPath)
	legacyTaskPath := filepath.Join(root, "cmd/strace-go/task_state.go")
	if _, err := os.Stat(legacyTaskPath); !os.IsNotExist(err) {
		t.Fatalf("legacy task_state.go still exists: %v", err)
	}

	if !strings.Contains(ownerSource, "type traceTaskLifecycleState struct") {
		t.Fatal("task lifecycle owner is missing")
	}
	for _, field := range []string{
		"\ttasks",
		"\tpendingForks",
		"\tlifecyclePending",
		"\tcommandTargetPID",
		"\tlifecycleExited",
		"\ttrackForkIdentity",
	} {
		if strings.Contains(stateSource, field) {
			t.Fatalf("TraceState still owns task lifecycle field %q", field)
		}
	}
	for _, required := range []string{
		"\ttasks",
		"\tpendingForks",
		"\tlifecyclePending",
		"\tcommandTargetPID",
		"\tlifecycleExited",
		"applyFork(",
		"applyExec(",
		"applyTaskExit(",
		"resolveForkIdentity(",
		"TargetLifecycleQuiescent",
	} {
		if !strings.Contains(ownerSource, required) {
			t.Fatalf("task lifecycle owner missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"type TaskState struct",
		"func (st *TraceState) ensureTaskState(",
		"func (st *TraceState) applyLifecycleEvent(",
		"func (st *TraceState) noteSyscallTask(",
	} {
		if strings.Contains(attachSource, forbidden) {
			t.Fatalf("attach state file still owns task lifecycle symbol %q", forbidden)
		}
	}
	for _, required := range []string{
		"\ttargets",
		"\texitReader",
		"\treaderEnabled",
		"refreshTargets(",
	} {
		if !strings.Contains(attachSource, required) {
			t.Fatalf("attach state boundary lost %q", required)
		}
	}
}
