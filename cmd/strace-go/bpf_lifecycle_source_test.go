package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFLifecycleHandlersHaveDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	lifecycleSource := readTextFile(t, filepath.Join(root, "bpf/lifecycle_dispatch.h"))
	stateSource := readTextFile(t, filepath.Join(root, "bpf/lifecycle_state.h"))
	pendingSource := readTextFile(t, filepath.Join(root, "bpf/pending_state.h"))
	if !strings.Contains(straceSource, `#include "lifecycle_dispatch.h"`) {
		t.Fatal("strace.c must include the lifecycle dispatch header")
	}
	if !strings.Contains(straceSource, `#include "lifecycle_state.h"`) {
		t.Fatal("strace.c must include the lifecycle state header")
	}
	for _, name := range []string{
		"trace_sched_process_fork",
		"trace_sched_process_exec",
		"trace_sched_process_exit",
		"trace_sched_process_free",
	} {
		if !strings.Contains(lifecycleSource, "int "+name+"(") {
			t.Fatalf("lifecycle dispatch header missing %s", name)
		}
		if strings.Contains(straceSource, "int "+name+"(") {
			t.Fatalf("strace.c still owns lifecycle handler %s", name)
		}
	}
	for _, section := range []string{
		`SEC("tracepoint/sched/sched_process_fork")`,
		`SEC("tracepoint/sched/sched_process_exec")`,
		`SEC("tracepoint/sched/sched_process_exit")`,
		`SEC("tracepoint/sched/sched_process_free")`,
	} {
		if !strings.Contains(lifecycleSource, section) {
			t.Fatalf("lifecycle dispatch header missing section %s", section)
		}
	}
	for _, name := range []string{
		"clear_armed_fork_parent",
		"clear_process_lifecycle_state",
		"clear_lifecycle_task_state",
	} {
		if !strings.Contains(stateSource, "void "+name+"(") {
			t.Fatalf("lifecycle state header missing %s", name)
		}
		if strings.Contains(pendingSource, "void "+name+"(") {
			t.Fatalf("pending state header still owns lifecycle cleanup %s", name)
		}
	}
}
