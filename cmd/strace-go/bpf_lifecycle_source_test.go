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
	if !strings.Contains(straceSource, `#include "lifecycle_dispatch.h"`) {
		t.Fatal("strace.c must include the lifecycle dispatch header")
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
}
