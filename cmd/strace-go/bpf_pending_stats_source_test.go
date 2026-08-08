package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 源码门禁：pending_syscalls 的每次写入失败都必须计入 stats，防止 map 满时静默丢数据。
func TestBPFPendingSaveChecksUpdateResult(t *testing.T) {
	root := repoRootForTest(t)
	headers := map[string]string{
		"bpf/syscall_direct_event_v2.h":         loadBPFSources(t).directHeader,
		"bpf/syscall_msg_direct_event_v2.h":     readTextFile(t, filepath.Join(root, "bpf/syscall_msg_direct_event_v2.h")),
		"bpf/syscall_network_direct_event_v2.h": readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h")),
	}
	for name, header := range headers {
		if !strings.Contains(header, "bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY) != 0") ||
			!strings.Contains(header, "record_pending_update_fail()") {
			t.Fatalf("%s does not check pending_syscalls update result and record failure", name)
		}
	}
}

func TestBPFStatsHasPendingUpdateFailCounter(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 pending_update_fail;") {
		t.Fatal("bpf/strace.c bpf_stats missing pending_update_fail counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_pending_update_fail(void)") {
		t.Fatal("bpf/strace.c missing record_pending_update_fail helper")
	}
}

func TestBPFOrphanExitIsFilteredAndCounted(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 orphan_exit;") {
		t.Fatal("bpf/strace.c bpf_stats missing orphan_exit counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_orphan_exit(void)") {
		t.Fatal("bpf/strace.c missing record_orphan_exit helper")
	}
	exitBody, ok := bpfFunctionBody(src.straceSource, "trace_sys_exit")
	if !ok {
		t.Fatal("bpf/strace.c missing trace_sys_exit body")
	}
	for _, snippet := range []string{
		"if (!is_lifecycle_task_tracked(pid, tid)) return 0;",
		"if (!should_trace_syscall((u32)ctx->id, cfg)",
		"record_orphan_exit();",
	} {
		if !strings.Contains(exitBody, snippet) {
			t.Fatalf("trace_sys_exit orphan path missing %q", snippet)
		}
	}
}

func TestBPFPendingExitIdentityIsValidatedAndCleaned(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 pending_mismatch;") {
		t.Fatal("bpf/strace.c bpf_stats missing pending_mismatch counter")
	}
	for _, snippet := range []string{
		"static __always_inline void record_pending_mismatch(void)",
		"lookup_pending_syscall_for_exit(",
		"validate_pending_syscall_exit(",
		"pending->sys_id == sys_id && pending->tid == pending_tid",
		"bpf_map_delete_elem(&pending_syscalls, &pending_tid);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF pending identity guard missing %q", snippet)
		}
	}
}
