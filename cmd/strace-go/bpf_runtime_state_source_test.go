package main

import (
	"path/filepath"
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
		"arm_parent && *arm_parent != 0 && *arm_parent == parent_pid",
		"bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);",
		"u32 parent_pid = (u32)(bpf_get_current_pid_tgid() >> 32);",
	} {
		if !strings.Contains(src.straceSource, snippet) {
			t.Fatalf("BPF source missing next-fork arm snippet %q", snippet)
		}
	}
}

func TestBPFAioSubmitNestedCaptureGate(t *testing.T) {
	src := loadBPFSources(t)
	aioHeader := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/syscall_aio_direct_event_v2.h"))
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
