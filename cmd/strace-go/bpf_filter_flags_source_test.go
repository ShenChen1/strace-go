package main

import (
	"strings"
	"testing"
)

func TestBPFFilterFlagsOwnPreExecState(t *testing.T) {
	source := readCombinedBPFSources(t)
	for _, snippet := range []string{
		"#define FILTER_TASK_TRACKED 1",
		"#define FILTER_TASK_PRE_EXEC 2",
		"lookup_lifecycle_task_filter_flags(u32 pid, u32 tid)",
		"static __always_inline int is_pre_exec_suppressed_syscall(",
		"u32 *filter_flags,",
		"install_pre_exec_filter(child_pid)",
		"install_tracked_filter(child_pid)",
		"clear_pre_exec_filter(tid)",
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("BPF source missing merged filter-state snippet %q", snippet)
		}
	}
	if strings.Contains(source, "pre_exec_map") {
		t.Fatal("BPF source must not keep a dedicated pre_exec_map")
	}
}

func TestBPFRawDispatchUsesOneFilterLookup(t *testing.T) {
	source := readCombinedBPFSources(t)
	for _, name := range []string{"trace_sys_enter", "trace_sys_exit"} {
		body, ok := bpfFunctionBody(source, name)
		if !ok {
			t.Fatalf("BPF source missing %s body", name)
		}
		for _, snippet := range []string{
			"u32 *filter_flags = lookup_lifecycle_task_filter_flags(pid, tid);",
			"if (!filter_flags) return 0;",
			"is_pre_exec_suppressed_syscall(filter_flags, sys_id)",
		} {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s missing merged filter gate %q", name, snippet)
			}
		}
		if strings.Contains(body, "is_lifecycle_task_tracked(pid, tid)") {
			t.Fatalf("%s must not perform a second filter lookup", name)
		}
	}
}
