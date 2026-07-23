package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFClone3PayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	clone3DirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_clone3_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_CLONE3 435",
		`#include "syscall_clone3_direct_event_v2.h"`,
		"is_clone3_direct_syscall(sys_id)",
		"emit_clone3_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_clone3_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing clone3 direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"CLONE3_DIRECT_ARGS_MAX 256",
		"is_clone3_direct_syscall(",
		"capture_clone3_args_tlv_direct(",
		"payload_tlv_clamp_u32(requested_len)",
		"payload_tlv_copy_len(requested_len, CLONE3_DIRECT_ARGS_MAX)",
		"PAYLOAD_TLV_KIND_STRUCT",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(payload_data, copied_len",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(clone3DirectHeader, snippet) {
			t.Fatalf("clone3 direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [clone3]",
		"case 435: /* clone3 */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("clone3 still uses old fixed-window rule %q", legacyRule)
		}
	}
}
