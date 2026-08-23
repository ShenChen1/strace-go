package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfTaskFdQueryOwnsExitBufferString(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_task_fd_query_exit_direct_event_v2.h"))
	enter := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	for _, snippet := range []string{
		`#include "syscall_bpf_task_fd_query_exit_direct_event_v2.h"`,
		"BPF_DIRECT_TASK_FD_QUERY 20",
		"BPF_DIRECT_TASK_FD_QUERY_BUF_OUT_ARG 137",
		"BPF_DIRECT_TASK_FD_QUERY_ATTR_OUT_ARG 138",
		"BPF_DIRECT_TASK_FD_QUERY_ATTR_MAX 64",
		"BPF_DIRECT_TASK_FD_QUERY_BUF_OFF 16",
		"BPF_DIRECT_TASK_FD_QUERY_BUF_LEN_OFF 12",
		"BPF_DIRECT_TASK_FD_QUERY_BUF_MAX 512",
		"emit_bpf_task_fd_query_exit_event_v2_direct(",
		"bpf_attr_read_u64_direct(",
		"bpf_attr_read_u32_direct(",
		"bpf_probe_read_user_str(",
		"capture_bpf_exit_bytes_tlv_direct(",
		"lookup_pending_syscall_aux0(p->tid)",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(provider+exit, snippet) {
			t.Fatalf("BPF task-fd-query provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF task-fd-query output")
	}
	for _, snippet := range []string{
		"ctx->args[0] == BPF_DIRECT_TASK_FD_QUERY",
		"BPF_DIRECT_TASK_FD_QUERY_BUF_LEN_OFF",
		"save_pending_syscall_aux(tid, buf_len)",
	} {
		if !strings.Contains(enter, snippet) {
			t.Fatalf("BPF task-fd-query enter snapshot missing %q", snippet)
		}
	}
}
