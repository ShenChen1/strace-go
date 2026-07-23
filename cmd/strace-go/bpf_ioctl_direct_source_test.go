package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFIoctlPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	ioctlDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_ioctl_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_IOCTL 16",
		`#include "syscall_ioctl_direct_event_v2.h"`,
		"is_ioctl_direct_syscall(sys_id)",
		"emit_ioctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_ioctl_direct_syscall(sys_id) ||",
		"emit_ioctl_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing ioctl direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"IOCTL_DIRECT_BYTES_MAX 512",
		"IOCTL_DIRECT_ZERO_SIZE_LEN 128",
		"IOCTL_DIRECT_SIZE_SHIFT 16",
		"IOCTL_DIRECT_SIZE_MASK 0x3fff",
		"is_ioctl_direct_syscall(",
		"ioctl_direct_user_len(",
		"capture_ioctl_arg_tlv_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(payload_data, copied_len",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(ioctlDirectHeader, snippet) {
			t.Fatalf("ioctl direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [ioctl]",
		"case 16: /* ioctl */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("ioctl still uses old fixed-window rule %q", legacyRule)
		}
	}
}
