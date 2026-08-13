package main

import (
	"strings"
	"testing"
)

func TestBPFFDStateTrackingGate(t *testing.T) {
	src := loadBPFSources(t)
	for _, snippet := range []string{
		"#define CONFIG_FD_STATE 64",
		"is_fd_state_direct_syscall(",
		"is_fd_state_tracked(sys_id, cfg)",
		"#define SYS_DUP 32",
		"#define SYS_DUP2 33",
		"#define SYS_DUP3 292",
		"#define SYS_CLOSE_RANGE 436",
		"#define SYS_EVENTFD 284",
		"#define SYS_EVENTFD2 290",
		"#define SYS_EPOLL_CREATE 213",
		"#define SYS_TIMERFD_CREATE 283",
		"#define SYS_EPOLL_CREATE1 291",
		"#define SYS_INOTIFY_INIT 253",
		"#define SYS_INOTIFY_INIT1 294",
		"#define SYS_SIGNALFD 282",
		"#define SYS_SIGNALFD4 289",
		"case SYS_FCNTL:",
		"case SYS_CLOSE_RANGE:",
		"case SYS_EVENTFD:",
		"case SYS_EVENTFD2:",
		"case SYS_EPOLL_CREATE:",
		"case SYS_TIMERFD_CREATE:",
		"case SYS_EPOLL_CREATE1:",
		"case SYS_INOTIFY_INIT:",
		"case SYS_INOTIFY_INIT1:",
		"case SYS_SIGNALFD:",
		"case SYS_SIGNALFD4:",
		"case SYS_PIPE:",
		"case SYS_SOCKETPAIR:",
		"#define SYS_FCHDIR 81",
		"case SYS_OPENAT2:",
		"case SYS_FACCESSAT2:",
		"case SYS_NEWFSTATAT:",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF source missing fd-state tracking snippet %q", snippet)
		}
	}
	if !strings.Contains(src.straceSource,
		"!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)") {
		t.Fatal("sys_enter filter must bypass fd-state syscalls when fd state tracking is on")
	}
	for _, snippet := range []string{
		"} arm_fork_map SEC(\".maps\");",
		"arm_parent && *arm_parent != 0 && *arm_parent == parent_tgid",
		"bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY) != 0",
		"u64 parent_pid_tgid = bpf_get_current_pid_tgid();",
		"u32 parent_tid = (u32)parent_pid_tgid;",
		"is_lifecycle_task_tracked(parent_tgid, parent_tid)",
		"emit_lifecycle_event(LIFECYCLE_FORK, parent_tgid, parent_tid, parent_tgid, child_pid, 0);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF source missing next-fork arm snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"u64 pid_tgid = bpf_get_current_pid_tgid();",
		"u32 tid = (u32)pid_tgid;",
		"bpf_map_delete_elem(&pre_exec_map, &tid);",
		"emit_lifecycle_event(LIFECYCLE_EXEC, pid, tid, ctx->old_pid, tid, filename);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF source missing exec identity snippet %q", snippet)
		}
	}
}

func TestBPFLifecycleCleanupIsTIDScoped(t *testing.T) {
	source := readCombinedBPFSources(t)

	exitBody, ok := bpfFunctionBody(source, "trace_sched_process_exit")
	if !ok {
		t.Fatal("strace.c missing trace_sched_process_exit body")
	}
	if !strings.Contains(exitBody, "clear_lifecycle_task_state(pid, tid);") {
		t.Fatal("sched_process_exit must use TID-scoped lifecycle cleanup")
	}

	cleanupBody, ok := bpfFunctionBody(source, "clear_lifecycle_task_state")
	if !ok {
		t.Fatal("strace.c missing clear_lifecycle_task_state body")
	}
	for _, snippet := range []string{
		"bpf_map_delete_elem(&pending_syscalls, &tid);",
		"if (tid != pid)",
		"bpf_map_delete_elem(&pending_exec_map, &pid);",
	} {
		if !strings.Contains(cleanupBody, snippet) {
			t.Fatalf("lifecycle cleanup helper missing snippet %q", snippet)
		}
	}
	if strings.Contains(cleanupBody, "bpf_map_delete_elem(&pending_syscalls, &pid);") {
		t.Fatal("lifecycle cleanup helper must not delete pending state by TGID")
	}
	processCleanupBody, ok := bpfFunctionBody(source, "clear_process_lifecycle_state")
	if !ok {
		t.Fatal("pending_state.h missing process lifecycle cleanup helper")
	}
	for _, snippet := range []string{
		"bpf_map_delete_elem(&filter_map, &pid);",
		"bpf_map_delete_elem(&pending_exec_map, &pid);",
		"bpf_map_delete_elem(&main_exited_map, &pid);",
		"clear_armed_fork_parent(pid);",
	} {
		if !strings.Contains(processCleanupBody, snippet) {
			t.Fatalf("process lifecycle cleanup missing %q", snippet)
		}
	}
	armCleanupBody, ok := bpfFunctionBody(source, "clear_armed_fork_parent")
	if !ok {
		t.Fatal("pending_state.h missing armed parent cleanup helper")
	}
	for _, snippet := range []string{
		"*armed_parent != pid",
		"bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0",
	} {
		if !strings.Contains(armCleanupBody, snippet) {
			t.Fatalf("armed parent cleanup missing %q", snippet)
		}
	}

	freeBody, ok := bpfFunctionBody(source, "trace_sched_process_free")
	if !ok {
		t.Fatal("strace.c missing trace_sched_process_free body")
	}
	for _, snippet := range []string{
		"u64 pid_tgid = bpf_get_current_pid_tgid();",
		"u32 tid = (u32)pid_tgid;",
		"clear_lifecycle_task_state(pid, tid);",
		"emit_lifecycle_event(LIFECYCLE_FREE, pid, tid, pid, 0, 0);",
	} {
		if !strings.Contains(freeBody, snippet) {
			t.Fatalf("sched_process_free missing TID-scoped cleanup snippet %q", snippet)
		}
	}
}

func TestBPFSyscallEnterUsesTIDAwareFilter(t *testing.T) {
	source := loadBPFSources(t).straceSource
	enterBody, ok := bpfFunctionBody(source, "trace_sys_enter")
	if !ok {
		t.Fatal("strace.c missing trace_sys_enter body")
	}
	if !strings.Contains(enterBody, "if (!is_lifecycle_task_tracked(pid, tid)) return 0;") {
		t.Fatal("trace_sys_enter must use the shared PID/TID-aware filter predicate")
	}
	if strings.Contains(enterBody, "bpf_map_lookup_elem(&filter_map, &pid)") {
		t.Fatal("trace_sys_enter must not use a TGID-only filter lookup")
	}
}

func TestBPFRawDispatchersSnapshotTaskIdentityOnce(t *testing.T) {
	source := loadBPFSources(t).straceSource
	for _, name := range []string{"trace_sys_enter", "trace_sys_exit"} {
		body, ok := bpfFunctionBody(source, name)
		if !ok {
			t.Fatalf("strace.c missing %s body", name)
		}
		if !strings.Contains(body, "u64 pid_tgid = bpf_get_current_pid_tgid();") {
			t.Fatalf("%s must snapshot pid/tid identity", name)
		}
		if got := strings.Count(body, "bpf_get_current_pid_tgid()"); got != 1 {
			t.Fatalf("%s calls bpf_get_current_pid_tgid %d times, want 1", name, got)
		}
		for _, snippet := range []string{
			"u32 tid = (u32)pid_tgid;",
			"u32 pid = (u32)(pid_tgid >> 32);",
		} {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s must derive identity from the snapshot: missing %q", name, snippet)
			}
		}
	}
}

func TestBPFExitDispatcherDefersPendingResolveToHandler(t *testing.T) {
	source := loadBPFSources(t).straceSource
	exitBody, ok := bpfFunctionBody(source, "trace_sys_exit")
	if !ok {
		t.Fatal("BPF source missing trace_sys_exit body")
	}
	for _, forbidden := range []string{
		"lookup_pending_syscall_for_exit(",
		"validate_pending_syscall_exit(",
	} {
		if strings.Contains(exitBody, forbidden) {
			t.Fatalf("trace_sys_exit must not resolve pending state before tail call: %q", forbidden)
		}
	}
	for _, required := range []string{
		"is_lifecycle_task_tracked(pid, tid)",
		"should_trace_syscall(sys_id, cfg)",
		"bpf_tail_call(ctx, &exit_progs, index);",
	} {
		if !strings.Contains(exitBody, required) {
			t.Fatalf("trace_sys_exit missing pre-dispatch gate %q", required)
		}
	}
	lifecycleGate := strings.Index(exitBody, "is_lifecycle_task_tracked(pid, tid)")
	tailCall := strings.Index(exitBody, "bpf_tail_call(ctx, &exit_progs, index);")
	if lifecycleGate < 0 || tailCall < lifecycleGate {
		t.Fatal("trace_sys_exit must filter tracked tasks before the exit tail call")
	}
	prologueStart := strings.Index(source, "#define EXIT_PROLOGUE")
	if prologueStart < 0 {
		t.Fatal("BPF source missing EXIT_PROLOGUE")
	}
	prologue := source[prologueStart:]
	if !strings.Contains(prologue, "u32 exit_sys_id = (u32)(ctx)->id;") {
		t.Fatal("EXIT_PROLOGUE must snapshot syscall id before helper calls")
	}
	if !strings.Contains(prologue, "record_unmatched_exit_if_needed(pid, tid") {
		t.Fatal("EXIT_PROLOGUE must own unmatched-exit accounting")
	}
	if !strings.Contains(prologue, "p, exit_sys_id, pid, pending_tid") {
		t.Fatal("EXIT_PROLOGUE must validate against the syscall id snapshot")
	}
}

func TestBPFTailCallProloguesSnapshotTaskIdentityOnce(t *testing.T) {
	source := loadBPFSources(t).straceSource
	for _, name := range []string{"ENTER_PROLOGUE", "EXIT_PROLOGUE"} {
		start := strings.Index(source, "#define "+name)
		if start < 0 {
			t.Fatalf("BPF source missing %s macro", name)
		}
		body := source[start:]
		if end := strings.Index(body, "\n\nSEC("); end >= 0 {
			body = body[:end]
		}
		if !strings.Contains(body, "u64 pid_tgid = bpf_get_current_pid_tgid();") {
			t.Fatalf("%s must snapshot pid/tid identity", name)
		}
		if got := strings.Count(body, "bpf_get_current_pid_tgid()"); got != 1 {
			t.Fatalf("%s calls bpf_get_current_pid_tgid %d times, want 1", name, got)
		}
		for _, snippet := range []string{
			"u32 tid = (u32)pid_tgid;",
			"u32 pid = (u32)(pid_tgid >> 32);",
		} {
			if !strings.Contains(body, snippet) {
				t.Fatalf("%s must derive identity from the snapshot: missing %q", name, snippet)
			}
		}
	}
}

func TestBPFInitialForkArmIsExecOwned(t *testing.T) {
	source := readCombinedBPFSources(t)
	execBody, ok := bpfFunctionBody(source, "trace_sched_process_exec")
	if !ok {
		t.Fatal("strace.c missing trace_sched_process_exec body")
	}
	lookup := "u32 *pre_exec = bpf_map_lookup_elem(&pre_exec_map, &tid);"
	if !strings.Contains(execBody, lookup) {
		t.Fatalf("exec handler must load the armed-child owner marker %q", lookup)
	}
	ownerGuard := strings.Index(execBody, "if (pre_exec) {")
	deleteMarker := strings.Index(execBody, "bpf_map_delete_elem(&pre_exec_map, &tid);")
	clearArm := strings.Index(execBody, "if (arm_parent && *arm_parent != 0) {")
	if ownerGuard < 0 || deleteMarker < ownerGuard || clearArm < ownerGuard {
		t.Fatal("exec handler must delete the marker and clear arm only inside the owner guard")
	}
	if strings.Contains(execBody, "if (tracked) {\n        // IMPACT: always lift pre-exec suppression") {
		t.Fatal("exec handler must not clear the arm for every tracked exec")
	}
}

func TestBPFPreExecSuppressionIsSymmetric(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "static __always_inline int is_pre_exec_suppressed_syscall(") {
		t.Fatal("strace.c missing shared pre-exec suppression helper")
	}

	enterBody, ok := bpfFunctionBody(src.straceSource, "trace_sys_enter")
	if !ok {
		t.Fatal("strace.c missing trace_sys_enter body")
	}
	if !strings.Contains(enterBody, "is_pre_exec_suppressed_syscall(pid, sys_id)") {
		t.Fatal("trace_sys_enter must use the shared pre-exec suppression helper")
	}
	if strings.Contains(enterBody, "bpf_map_lookup_elem(&pre_exec_map, &pid)") {
		t.Fatal("trace_sys_enter must not duplicate pre-exec map lookup logic")
	}

	exitBody, ok := bpfFunctionBody(src.straceSource, "trace_sys_exit")
	if !ok {
		t.Fatal("strace.c missing trace_sys_exit body")
	}
	if !strings.Contains(exitBody, "is_pre_exec_suppressed_syscall(pid, sys_id)") {
		t.Fatal("trace_sys_exit must use the shared pre-exec suppression helper")
	}
}

func TestBPFAioSubmitNestedCaptureGate(t *testing.T) {
	src := loadBPFSources(t)
	aioHeader := readAioDirectEventSources(t)
	for _, snippet := range []string{
		"enter_aio",
		"enter_aio_iovec",
		"enter_aio_buf",
		"AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX",
		"AIO_SUBMIT_DIRECT_BUF_ARG_BASE 60",
		"capture_aio_submit_iocb_iovec_tlv_direct(",
		"capture_aio_submit_iocb_buf_tlv_direct(",
		"PAYLOAD_TLV_KIND_IOVEC",
	} {
		if !strings.Contains(src.straceSource, snippet) && !strings.Contains(aioHeader, snippet) {
			t.Fatalf("AIO nested capture missing snippet %q", snippet)
		}
	}
}
