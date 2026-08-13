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
		"bpf/syscall_msg_direct_event_v2.h":     readMsgDirectEventSources(t),
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

func TestBPFTrackedMapUpdatesAreChecked(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 lifecycle_map_update_fail;") {
		t.Fatal("bpf/strace.c bpf_stats missing lifecycle map update counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_lifecycle_map_update_fail(void)") {
		t.Fatal("bpf/strace.c missing lifecycle map update helper")
	}
	forkBody, ok := bpfFunctionBody(src.straceSource, "trace_sched_process_fork")
	if !ok {
		t.Fatal("strace.c missing trace_sched_process_fork body")
	}
	for _, snippet := range []string{
		"if (bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY) != 0)",
		"else if (bpf_map_update_elem(&pre_exec_map, &child_pid, &val, BPF_ANY) != 0)",
		"bpf_map_delete_elem(&filter_map, &child_pid);",
		"record_lifecycle_map_update_fail();",
	} {
		if !strings.Contains(forkBody, snippet) {
			t.Fatalf("fork lifecycle update gate missing %q", snippet)
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
	if !strings.Contains(src.straceSource, "static __always_inline void record_orphan_exit(void)") {
		t.Fatal("bpf/strace.c missing record_orphan_exit helper")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_unmatched_exit_if_needed(") {
		t.Fatal("bpf/pending_state.h missing unmatched-exit helper")
	}
	for _, snippet := range []string{
		"if (!is_lifecycle_task_tracked(pid, tid)) return 0;",
		"if (!should_trace_syscall(sys_id, cfg)",
		"record_orphan_exit();",
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
		"ret_value == -512 || ret_value == -513 ||",
		"ret_value == -514 || ret_value == -516;",
	} {
		if !strings.Contains(combined, snippet) {
			t.Fatalf("orphan lifecycle classification missing %q", snippet)
		}
	}
	helperStart := strings.Index(unmatched, "static __always_inline void record_unmatched_exit_if_needed(")
	classification := strings.Index(unmatched[helperStart:], "if (is_expected_unmatched_exit(sys_id, ret_value)) return;")
	count := strings.Index(unmatched[helperStart:], "record_orphan_exit();")
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
	orphanIndex := strings.Index(unmatched, "record_orphan_exit();")
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
		"bpf_map_delete_elem(&pending_syscalls, &pending_tid);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF pending identity guard missing %q", snippet)
		}
	}
}
