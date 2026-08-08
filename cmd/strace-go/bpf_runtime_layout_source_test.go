package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFRuntimeModulesOwnCoreDefinitions(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	abi := read("runtime_abi.h")
	stats := read("runtime_stats.h")
	lifecycle := read("lifecycle_event_v2.h")
	pending := read("pending_state.h")
	entry := read("strace.c")

	for name, source := range map[string]string{
		"runtime_abi.h":        abi,
		"runtime_stats.h":      stats,
		"lifecycle_event_v2.h": lifecycle,
		"pending_state.h":      pending,
	} {
		if !strings.Contains(source, "#ifndef STRACE_GO_") || !strings.Contains(source, "#endif") {
			t.Fatalf("%s must have an include guard", name)
		}
	}
	for _, snippet := range []string{
		"struct pending_syscall {",
		"struct event_v2_header {",
		"} events SEC(\".maps\");",
		"} pending_syscalls SEC(\".maps\");",
	} {
		if !strings.Contains(abi, snippet) {
			t.Fatalf("runtime_abi.h missing ABI-owned definition %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline struct bpf_stats *lookup_stats(void)",
		"record_pending_update_fail(void)",
		"record_pending_mismatch(void)",
	} {
		if !strings.Contains(stats, snippet) {
			t.Fatalf("runtime_stats.h missing stats-owned helper %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_lifecycle_event_v2_direct(",
		"is_lifecycle_task_tracked(",
	} {
		if !strings.Contains(lifecycle, snippet) {
			t.Fatalf("lifecycle_event_v2.h missing lifecycle-owned helper %q", snippet)
		}
	}
	for _, snippet := range []string{
		"lookup_pending_syscall_for_exit(",
		"validate_pending_syscall_exit(",
		"clear_lifecycle_task_state(",
	} {
		if !strings.Contains(pending, snippet) {
			t.Fatalf("pending_state.h missing pending-owned helper %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"struct pending_syscall {",
		"struct bpf_stats {",
		"struct event_v2_header {",
		"static __always_inline int should_trace_syscall(",
		"static __always_inline void clear_lifecycle_task_state(",
	} {
		if strings.Contains(entry, forbidden) {
			t.Fatalf("strace.c must not re-own runtime definition %q", forbidden)
		}
	}
}

func TestBPFRuntimeEntryFileStaysSmall(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	if lines := strings.Count(source, "\n") + 1; lines > 500 {
		t.Fatalf("bpf/strace.c lines = %d, want <= 500", lines)
	}
}
