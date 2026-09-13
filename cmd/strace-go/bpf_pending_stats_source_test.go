package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 源码门禁：task storage 创建失败必须计入 stats，防止 pending state 静默丢失。
func TestBPFPendingSaveChecksUpdateResult(t *testing.T) {
	root := repoRootForTest(t)
	headers := map[string]string{
		"bpf/syscall_direct_event_v2.h": loadBPFSources(t).directHeader,
		"bpf/syscall_msg_direct_event_v2.h": readMsgDirectEventSources(t) +
			"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h")),
		"bpf/syscall_network_direct_event_v2.h": readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h")) +
			"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h")),
	}
	for name, header := range headers {
		if !strings.Contains(header, "save_pending_syscall_value(&p)") ||
			!strings.Contains(header, "record_pending_update_fail()") {
			t.Fatalf("%s does not route pending state through task storage failure accounting", name)
		}
	}
	source := readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h"))
	body, ok := bpfFunctionBody(source, "save_pending_syscall_value")
	if !ok {
		t.Fatal("BPF source missing save_pending_syscall_value body")
	}
	if !strings.Contains(body, "bpf_map_update_elem(&pending_stack_map, &pending->tid, &pending->stack_id, BPF_ANY) != 0") {
		t.Fatal("pending stack map update failure is not checked")
	}
}

func TestBPFPendingAuxSaveChecksUpdateResult(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h"))
	for _, snippet := range []string{
		"struct pending_task_state *state = current_pending_task_state();",
		"state->aux0 = aux0;",
		"record_pending_update_fail()",
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("auxiliary pending state update is missing failure accounting %q", snippet)
		}
	}
}

func TestBPFPendingTaskStorageCleanupIsCentralized(t *testing.T) {
	source := readCombinedBPFSources(t)
	want := map[string][]string{
		"validate_pending_syscall_exit": {
			"clear_pending_task_state();",
		},
		"consume_pending_syscall": {
			"clear_pending_task_state();",
		},
		"clear_replaced_leader_task_state": {
			"clear_pending_task_state();",
		},
		"clear_lifecycle_task_state": {
			"clear_pending_task_state();",
		},
	}
	for name, snippets := range want {
		body, ok := bpfFunctionBody(source, name)
		if !ok {
			t.Fatalf("BPF source missing %s body", name)
		}
		for _, snippet := range snippets {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s cleanup is missing %q", name, snippet)
			}
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

func TestBPFTrackedMapUpdatesAreChecked(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 lifecycle_map_update_fail;") {
		t.Fatal("bpf/strace.c bpf_stats missing lifecycle map update counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_lifecycle_map_update_fail(void)") {
		t.Fatal("bpf/strace.c missing lifecycle map update helper")
	}
	for _, field := range []string{
		"u64 lifecycle_fork_seen;",
		"u64 lifecycle_fork_parent_tracked;",
		"u64 lifecycle_fork_parent_untracked;",
		"u64 lifecycle_fork_child_filter_installed;",
		"u64 lifecycle_fork_child_filter_failed;",
		"u64 lifecycle_exec_seen;",
		"u64 lifecycle_exec_untracked;",
		"u64 lifecycle_exit_seen;",
		"u64 lifecycle_exit_untracked;",
	} {
		if !strings.Contains(src.straceSource, field) {
			t.Fatalf("bpf_stats missing lifecycle diagnostic field %q", field)
		}
	}
	forkBody, ok := bpfFunctionBody(src.straceSource, "trace_sched_process_fork")
	if !ok {
		t.Fatal("strace.c missing trace_sched_process_fork body")
	}
	for _, snippet := range []string{
		"install_pre_exec_filter(child_pid);",
		"record_lifecycle_fork_child_filter(install_tracked_filter(child_pid));",
	} {
		if !strings.Contains(forkBody, snippet) {
			t.Fatalf("fork lifecycle update gate missing %q", snippet)
		}
	}
	for _, name := range []string{"install_pre_exec_filter", "install_tracked_filter"} {
		body, ok := bpfFunctionBody(readCombinedBPFSources(t), name)
		if !ok || !strings.Contains(body, "bpf_map_update_elem(&filter_map") ||
			!strings.Contains(body, "record_lifecycle_map_update_fail();") {
			t.Fatalf("%s must check filter map update failures", name)
		}
	}
	enterBody, ok := bpfFunctionBody(src.straceSource, "enter_terminating")
	if !ok || !strings.Contains(enterBody, "bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY) != 0") {
		t.Fatal("terminating path must check main_exited_map update")
	}
	execEnterBody, ok := bpfFunctionBody(src.straceSource, "enter_exec")
	if !ok || !strings.Contains(execEnterBody, "bpf_map_update_elem(&pending_exec_map, &pid, &tid, BPF_ANY) != 0") {
		t.Fatal("exec path must check pending_exec_map update")
	}
	execBody, ok := bpfFunctionBody(src.straceSource, "trace_sched_process_exec")
	if !ok || !strings.Contains(execBody, "bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0") {
		t.Fatal("exec lifecycle path must check arm cleanup update")
	}
	pendingBody, ok := bpfFunctionBody(readCombinedBPFSources(t), "clear_armed_fork_parent")
	if !ok || !strings.Contains(pendingBody, "bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0") {
		t.Fatal("pending cleanup path must check arm cleanup update")
	}
}

func TestBPFOrphanExitIsFilteredAndCounted(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 orphan_exit;") {
		t.Fatal("bpf/strace.c bpf_stats missing orphan_exit counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_orphan_exit(") {
		t.Fatal("bpf/strace.c missing record_orphan_exit helper")
	}
	runtimeStats := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/runtime_stats.h"))
	orphanStart := strings.Index(runtimeStats, "static __always_inline void record_orphan_exit(")
	orphanEnd := strings.Index(runtimeStats, "static __always_inline void record_pending_mismatch(void)")
	if orphanStart < 0 || orphanEnd <= orphanStart {
		t.Fatal("bpf/strace.c missing record_orphan_exit body")
	}
	if strings.Contains(runtimeStats[orphanStart:orphanEnd], "record_event_integrity_loss()") {
		t.Fatal("orphan diagnostics must not advance the producer loss epoch")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_unmatched_exit_if_needed(") {
		t.Fatal("bpf/pending_state.h missing unmatched-exit helper")
	}
	for _, snippet := range []string{
		"if (!is_lifecycle_task_tracked(pid, tid))",
		"if (!should_trace_syscall(sys_id, cfg)",
		"record_orphan_exit(pid, tid, sys_id, ret_value, ORPHAN_REASON_NO_PENDING);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("unmatched-exit helper missing %q", snippet)
		}
	}
}

func TestBPFOrphanExitIgnoresExpectedLifecycleReturns(t *testing.T) {
	src := loadBPFSources(t)
	combined := readCombinedBPFSources(t) + "\n" + src.directHeader
	root := repoRootForTest(t)
	unmatched := readTextFile(t, filepath.Join(root, "bpf/pending_state.h"))
	if !strings.Contains(unmatched, "static __always_inline void record_unmatched_exit_if_needed(") {
		t.Fatal("bpf/pending_state.h missing unmatched-exit helper")
	}
	for _, snippet := range []string{
		"static __always_inline int is_expected_unmatched_exit(u32 sys_id, s64 ret_value)",
		"is_terminating_direct_syscall(sys_id)",
		"return sys_id == SYS_CLONE || sys_id == SYS_CLONE3 ||",
		"sys_id == SYS_FORK || sys_id == SYS_VFORK;",
		"is_process_creation_direct_syscall(sys_id) && ret_value == 0",
		"is_exec_payload_direct_syscall(sys_id) && ret_value == 0",
		"ret_value == -512 || ret_value == -513 ||",
		"ret_value == -514 || ret_value == -516;",
	} {
		if !strings.Contains(combined, snippet) {
			t.Fatalf("orphan lifecycle classification missing %q", snippet)
		}
	}
	helperStart := strings.Index(unmatched, "static __always_inline void record_unmatched_exit_if_needed(")
	classification := strings.Index(unmatched[helperStart:], "if (is_expected_unmatched_exit(sys_id, ret_value)) return;")
	count := strings.Index(unmatched[helperStart:], "record_orphan_exit(pid, tid, sys_id, ret_value, ORPHAN_REASON_NO_PENDING);")
	if classification < 0 || count < classification {
		t.Fatal("expected unmatched exits must be classified before orphan_exit is recorded")
	}
}

func TestBPFOrphanExitIgnoresAttachTeardownAfterExitFact(t *testing.T) {
	root := repoRootForTest(t)
	unmatched := readTextFile(t, filepath.Join(root, "bpf/pending_state.h"))
	guard := "bpf_map_lookup_elem(&attach_exited_map, &tid)"
	if !strings.Contains(unmatched, guard) {
		t.Fatalf("unmatched exit helper must consult attach exit fact %q", guard)
	}
	guardIndex := strings.Index(unmatched, guard)
	orphanIndex := strings.Index(unmatched, "record_orphan_exit(pid, tid, sys_id, ret_value, ORPHAN_REASON_NO_PENDING);")
	if guardIndex < 0 || orphanIndex < 0 || guardIndex > orphanIndex {
		t.Fatalf("attach teardown guard must precede orphan accounting: guard=%d orphan=%d", guardIndex, orphanIndex)
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
		"clear_pending_task_state();",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF pending identity guard missing %q", snippet)
		}
	}
}

func TestBPFNonLeaderExecUsesTaskStorageHandoff(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/pending_state.h"))
	for _, snippet := range []string{
		"struct pending_task_state *state = current_pending_task_state();",
		"ret_value == 0 && is_exec_payload_direct_syscall(pending->sys_id)",
		"bpf_map_lookup_elem(&pending_exec_map, &pid)",
		"*pending_exec_lookup = 1;",
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("non-leader exec task handoff is missing %q", snippet)
		}
	}
}
