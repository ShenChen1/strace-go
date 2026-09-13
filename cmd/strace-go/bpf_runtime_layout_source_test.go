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
	lifecycleState := read("lifecycle_state.h")
	entry := read("strace.c")

	for name, source := range map[string]string{
		"runtime_abi.h":        abi,
		"runtime_stats.h":      stats,
		"lifecycle_event_v2.h": lifecycle,
		"pending_state.h":      pending,
		"lifecycle_state.h":    lifecycleState,
	} {
		if !strings.Contains(source, "#ifndef STRACE_GO_") || !strings.Contains(source, "#endif") {
			t.Fatalf("%s must have an include guard", name)
		}
	}
	for _, snippet := range []string{
		"struct pending_syscall {",
		"struct pending_task_state {",
		"struct event_v2_header {",
		"__uint(max_entries, 1 << 28);",
		"} events SEC(\".maps\");",
		"} pending_task_storage SEC(\".maps\");",
	} {
		if !strings.Contains(abi, snippet) {
			t.Fatalf("runtime_abi.h missing ABI-owned definition %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline struct bpf_stats *lookup_stats(void)",
		"record_pending_update_fail(void)",
		"record_lifecycle_map_update_fail(void)",
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
		"pending_syscall_duration(",
		"consume_pending_syscall(",
	} {
		if !strings.Contains(pending, snippet) {
			t.Fatalf("pending_state.h missing pending-owned helper %q", snippet)
		}
	}
	for _, snippet := range []string{
		"clear_armed_fork_parent(",
		"clear_process_lifecycle_state(",
		"clear_lifecycle_task_state(",
	} {
		if !strings.Contains(lifecycleState, snippet) {
			t.Fatalf("lifecycle_state.h missing lifecycle-owned helper %q", snippet)
		}
		if strings.Contains(pending, snippet) {
			t.Fatalf("pending_state.h still owns lifecycle helper %q", snippet)
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

func TestBPFPendingTaskStateOwnsAuxiliaryMetadata(t *testing.T) {
	root := repoRootForTest(t)
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	network := readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h"))
	msg := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_core_direct_event_v2.h"))
	stateStart := strings.Index(abi, "struct pending_task_state {")
	if stateStart < 0 {
		t.Fatal("runtime_abi.h task-local pending state is missing")
	}
	stateEnd := strings.Index(abi[stateStart:], "};")
	if stateEnd < 0 {
		t.Fatal("runtime_abi.h pending task state is unterminated")
	}
	state := abi[stateStart : stateStart+stateEnd]
	for _, snippet := range []string{"struct pending_syscall syscall;", "u32 aux0;", "u32 valid;"} {
		if !strings.Contains(state, snippet) {
			t.Fatalf("pending task state missing %q", snippet)
		}
	}
	if strings.Contains(abi, "pending_syscall_aux_map SEC(\".maps\")") {
		t.Fatal("task-local pending state must not retain an auxiliary hash map")
	}
	for name, source := range map[string]string{"network": network, "msg": msg} {
		if !strings.Contains(source, "save_pending_syscall_aux(") {
			t.Fatalf("%s pending path does not save auxiliary metadata", name)
		}
	}
}

func TestBPFRuntimeSyscallNumbersAreGenerated(t *testing.T) {
	root := repoRootForTest(t)
	abi := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	generated := readTextFile(t, filepath.Join(root, "bpf/syscall_numbers_amd64_generated.h"))
	if !strings.Contains(abi, `#include "syscall_numbers_generated.h"`) {
		t.Fatal("runtime_abi.h must include generated syscall numbers")
	}
	if strings.Contains(abi, "#define SYS_READ ") {
		t.Fatal("runtime_abi.h still owns a hand-written syscall number")
	}
	for _, snippet := range []string{
		"#ifndef STRACE_GO_SYSCALL_NUMBERS_GENERATED_H",
		"#define SYS_READ 0",
		"#define SYS_STATMOUNT 457",
	} {
		if !strings.Contains(generated, snippet) {
			t.Fatalf("generated syscall header missing %q", snippet)
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
