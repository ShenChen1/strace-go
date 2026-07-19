package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAioSetupPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	aioDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_IO_SETUP 206",
		`#include "syscall_aio_direct_event_v2.h"`,
		"is_aio_setup_direct_syscall(sys_id)",
		"emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"is_aio_setup_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);",
		"is_aio_setup_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing io_setup direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"AIO_SETUP_DIRECT_CTX_SIZE 8",
		"capture_aio_setup_ctx_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(payload_data, AIO_SETUP_DIRECT_CTX_SIZE",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(aioDirectHeader, snippet) {
			t.Fatalf("AIO direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [io_setup]",
		"case 206: /* io_setup */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("io_setup still uses old fixed-window rule %q", legacyRule)
		}
	}
}
