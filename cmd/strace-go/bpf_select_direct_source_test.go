package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSelectPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	selectDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_select_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_SELECT 23",
		`#include "syscall_select_direct_event_v2.h"`,
		"is_select_direct_syscall(sys_id)",
		"emit_select_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_select_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_select_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing select direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"SELECT_DIRECT_FDSET_SIZE 128",
		"SELECT_DIRECT_TIMEVAL_SIZE 16",
		"SELECT_DIRECT_FDSET_ARG_BASE 1",
		"SELECT_DIRECT_FDSET_ARG_LAST 3",
		"is_select_direct_syscall(",
		"select_direct_fdset_user_len(",
		"s32 nfds = (s32)nfds_raw;",
		"capture_select_fdset_tlv_direct(",
		"capture_select_timeout_tlv_direct(",
		"capture_select_payloads_tlv_direct(",
		"emit_select_enter_event_v2_direct(",
		"emit_select_exit_event_v2_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(payload_data, 1",
		"bpf_probe_read_user(payload_data, SELECT_DIRECT_FDSET_SIZE",
		"bpf_probe_read_user(payload_data, SELECT_DIRECT_TIMEVAL_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);",
		"body.capture_len = payload_size;",
	} {
		if !strings.Contains(selectDirectHeader, snippet) {
			t.Fatalf("select direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [select, _newselect]",
		"case 23: /* select */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("select syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
