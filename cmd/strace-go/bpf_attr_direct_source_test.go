package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfAttrPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	bpfDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_BPF 321",
		`#include "syscall_bpf_direct_event_v2.h"`,
		"is_bpf_direct_syscall(sys_id)",
		"emit_bpf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_bpf_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing bpf direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"BPF_DIRECT_ATTR_MAX 512",
		"is_bpf_direct_syscall(",
		"capture_bpf_attr_tlv_direct(",
		"payload_tlv_clamp_u32(requested_len)",
		"payload_tlv_copy_len(requested_len, BPF_DIRECT_ATTR_MAX)",
		"PAYLOAD_TLV_KIND_BYTES",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(payload_data, copied_len",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(bpfDirectHeader, snippet) {
			t.Fatalf("bpf direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [bpf]",
		"case 321: /* bpf */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("bpf still uses old fixed-window rule %q", legacyRule)
		}
	}
}
