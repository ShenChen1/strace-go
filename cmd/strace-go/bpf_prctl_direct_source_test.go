package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPrctlPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	prctlDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_prctl_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_PRCTL 157",
		`#include "syscall_prctl_direct_event_v2.h"`,
		"is_prctl_direct_syscall(sys_id)",
		"emit_prctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_prctl_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_prctl_exit_event_v2_direct(p, ret_value, duration);",
		"is_prctl_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing prctl direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"PRCTL_DIRECT_NAME_SIZE 16",
		"PRCTL_DIRECT_UINT32_SIZE 4",
		"is_prctl_set_name_option(",
		"is_prctl_get_name_option(",
		"is_prctl_uint32_out_option(",
		"capture_prctl_name_tlv_direct(",
		"capture_prctl_uint32_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user_str(payload_data, PRCTL_DIRECT_NAME_SIZE",
		"bpf_probe_read_user(",
		"PRCTL_DIRECT_NAME_SIZE - 1",
		"n >= PRCTL_DIRECT_NAME_SIZE",
		"copied_len = PRCTL_DIRECT_NAME_SIZE - 1",
		"bpf_probe_read_user(payload_data, PRCTL_DIRECT_UINT32_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(prctlDirectHeader, snippet) {
			t.Fatalf("prctl direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [prctl]",
		"case 157: /* prctl */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("prctl still uses old fixed-window rule %q", legacyRule)
		}
	}
}
