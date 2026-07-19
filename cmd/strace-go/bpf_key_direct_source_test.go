package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFKeyPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	keyDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_key_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_ADD_KEY 248",
		"#define SYS_REQUEST_KEY 249",
		`#include "syscall_key_direct_event_v2.h"`,
		"is_key_direct_syscall(sys_id)",
		"emit_key_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_key_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) && !strings.Contains(keyDirectHeader, snippet) {
			t.Fatalf("BPF source missing key direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"KEY_DIRECT_TYPE_MAX 64",
		"KEY_DIRECT_DESCRIPTION_MAX 128",
		"KEY_DIRECT_PAYLOAD_MAX 256",
		"capture_key_string_tlv_direct(",
		"capture_key_bytes_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_BYTES",
		"bpf_probe_read_user_str(payload_data, max_len",
		"bpf_probe_read_user(payload_data, copied_len",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(keyDirectHeader, snippet) {
			t.Fatalf("key direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [add_key]",
		"syscalls: [request_key]",
		"case 248: /* add_key */",
		"case 249: /* request_key */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("key syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
