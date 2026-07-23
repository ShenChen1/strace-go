package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFcntlPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	fcntlDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_fcntl_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_FCNTL 72",
		`#include "syscall_fcntl_direct_event_v2.h"`,
		"is_fcntl_direct_syscall(sys_id)",
		"emit_fcntl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_fcntl_direct_syscall(sys_id) ||",
		"emit_fcntl_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing fcntl direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"FCNTL_DIRECT_SMALL_SIZE 8",
		"FCNTL_DIRECT_FLOCK_SIZE 32",
		"is_fcntl_direct_syscall(",
		"fcntl_direct_payload_size(",
		"capture_fcntl_struct_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(payload_data, struct_size",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(fcntlDirectHeader, snippet) {
			t.Fatalf("fcntl direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [fcntl, fcntl64]",
		"case 72: /* fcntl */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("fcntl still uses old fixed-window rule %q", legacyRule)
		}
	}
}
