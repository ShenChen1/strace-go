package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFExitEventCarriesTaskCPUDuration(t *testing.T) {
	root := repoRootForTest(t)
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	core := readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h"))

	for _, snippet := range []string{
		"u64 cpu_enter_time;",
		"u64 cpu_duration_ns;",
	} {
		if !strings.Contains(runtimeABI, snippet) {
			t.Fatalf("runtime ABI missing CPU timing field %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_CORE_READ(task, se.sum_exec_runtime)",
		"pending->cpu_enter_time = current_task_cpu_runtime();",
		"body->cpu_duration_ns = pending_syscall_cpu_duration(p);",
	} {
		if !strings.Contains(core, snippet) {
			t.Fatalf("shared event core missing CPU timing ownership %q", snippet)
		}
	}
}
