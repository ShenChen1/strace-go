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

func TestBPFNonLeaderExecPreservesProcessTrackingAcrossLeaderReplacement(t *testing.T) {
	source := readCombinedBPFSources(t)
	helper, ok := bpfFunctionBody(source, "is_exec_replaced_leader")
	if !ok {
		t.Fatal("lifecycle state missing exec-replaced leader predicate")
	}
	for _, snippet := range []string{
		"bpf_map_lookup_elem(&pending_exec_map, &pid)",
		"BPF_CORE_READ(task, signal, group_exec_task)",
		"BPF_CORE_READ(exec_task, pid)",
	} {
		if !strings.Contains(helper, snippet) {
			t.Fatalf("exec-replaced leader predicate missing %q", snippet)
		}
	}

	exitBody, ok := bpfFunctionBody(source, "trace_sched_process_exit")
	if !ok {
		t.Fatal("lifecycle dispatch missing sched_process_exit")
	}
	replacementGuard := strings.Index(exitBody, "is_exec_replaced_leader(task, pid, tid)")
	attachExit := strings.Index(exitBody, "mark_attach_task_exited(tid)")
	processCleanup := strings.Index(exitBody, "clear_lifecycle_task_state(pid, tid)")
	if replacementGuard < 0 || attachExit < replacementGuard || processCleanup < replacementGuard {
		t.Fatal("leader replacement must bypass attach exit and process cleanup")
	}
	if !strings.Contains(exitBody, "clear_replaced_leader_task_state(tid)") {
		t.Fatal("leader replacement must clear only the old leader TID state")
	}
}

func TestBPFFreeUsesTracepointTaskPID(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/lifecycle_dispatch.h"))
	body, ok := bpfFunctionBody(source, "trace_sched_process_free")
	if !ok {
		t.Fatal("lifecycle dispatch missing sched_process_free")
	}
	for _, snippet := range []string{
		"u32 tid = (u32)ctx->pid;",
		"is_lifecycle_task_tracked(tid, tid)",
		"clear_lifecycle_task_state(tid, tid);",
		"emit_lifecycle_event(LIFECYCLE_FREE, tid, tid, tid, 0, 0);",
	} {
		if !strings.Contains(body, snippet) {
			t.Fatalf("sched_process_free missing task-scoped snippet %q", snippet)
		}
	}
	if strings.Contains(body, "bpf_get_current_pid_tgid()") {
		t.Fatal("sched_process_free must not identify the freed task from current context")
	}
}
