package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMemfdCreatePayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	memfdDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_memfd_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_MEMFD_CREATE 319",
		`#include "syscall_memfd_direct_event_v2.h"`,
		"is_memfd_create_direct_syscall(sys_id)",
		"emit_memfd_create_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_memfd_create_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing memfd_create direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"MEMFD_CREATE_DIRECT_NAME_MAX 250",
		"capture_memfd_create_name_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"bpf_probe_read_user_str(payload_data, MEMFD_CREATE_DIRECT_NAME_MAX",
		"bpf_probe_read_user(payload_data, MEMFD_CREATE_DIRECT_NAME_MAX",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(memfdDirectHeader, snippet) {
			t.Fatalf("memfd_create direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [memfd_create]",
		"case 319: /* memfd_create */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("memfd_create still uses old fixed-window rule %q", legacyRule)
		}
	}
}
