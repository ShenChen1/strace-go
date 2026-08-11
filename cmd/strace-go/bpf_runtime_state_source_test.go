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
		"case SYS_FCNTL:",
		"case SYS_CLOSE_RANGE:",
		"case SYS_EVENTFD:",
		"case SYS_EVENTFD2:",
		"case SYS_EPOLL_CREATE:",
		"case SYS_TIMERFD_CREATE:",
		"case SYS_EPOLL_CREATE1:",
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
		"bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);",
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
	if !strings.Contains(exitBody, "is_pre_exec_suppressed_syscall(pid, (u32)ctx->id)") {
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
